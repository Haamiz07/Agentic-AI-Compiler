// =============================================================================
// AGentic_C Example: Cloud Security & Kernel Packet Filtering (Linux eBPF/XDP)
// File: examples/ebpf_ddos_packet_filter.cpp
// =============================================================================
//
// Real-World Industry Context (Cloudflare, Meta Katran, AWS Shield, Netflix):
//   Edge servers process 100M+ packets/sec directly in the NIC driver hook
//   (XDP — eXpress Data Path) using LLVM-compiled C/C++ eBPF programs.
//
// Why Standard `clang -O3` Breaks eBPF Verification:
//   Before loading bytecode into kernel space, the Linux Kernel Verifier
//   proves termination, bounded loops, and strict packet pointer bounds:
//     `(const uint8_t*)pkt_ptr + hdr_size <= (const uint8_t*)data_end`
//   Aggressive -O3 passes can reorder pointer arithmetic, hoist speculative
//   loads across bounds checks, emit non-inlined indirect calls, or bloat loop
//   bounds — causing the kernel verifier to REJECT the compiled binary with
//   `R1 offset is outside of the packet` or `invalid access to packet`.
//
// How AGentic_C Solves This:
//   1. Boss Agent classifies packet-rx paths as HOT (<100ns budget) and
//      telemetry/ACL reload paths as COLD (isolated from hot L1i cache).
//   2. Fixer Agent catches verifier/latency hazards (heap alloc LAP-001,
//      indirect std::function dispatch LAP-006, seq_cst atomics LAP-007,
//      branch-heavy nested parsing LAP-010, syscalls LAP-005).
//   3. SafeOptimizationController + CandidateValidator verify every LLVM pass
//      step-by-step against edge-case packet fixtures, automatically rolling back
//      any pass that violates safety or behavior invariants.
//
// Functions Overview:
//   on_xdp_rx_packet         → HOT  Main 100Mpps XDP ingress hook
//   parse_ethernet_ipv4_hdr  → HOT  Verifier-safe L2/L3/L4 header bounds parser
//   compute_flow_tuple_hash  → HOT  Clean 5-tuple FNV-1a/Murmur hash (SIMD-ready)
//   check_ip_blocklist_lpm   → HOT  Fixed-depth LPM CIDR prefix matcher
//   classify_syn_flood       → HOT  SYN flood gate + deliberate LAP-007/LAP-010
//   inspect_udp_amplification→ HOT  Amplification guard + deliberate LAP-006
//   update_token_bucket      → HOT  Verifier-bounded per-CPU rate limiter
//   load_acl_rules           → COLD Control-plane CIDR prefix rule loader
//   flush_xdp_ring_metrics   → COLD Per-CPU drop/pass statistics printer
//   generate_mitigation_report→ COLD Human-readable edge telemetry dump
//
// =============================================================================

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

// -----------------------------------------------------------------------------
// eBPF / XDP Verdict Codes & Protocol Constants
// -----------------------------------------------------------------------------

enum XdpAction : int {
    XDP_ABORTED  = 0,
    XDP_DROP     = 1,
    XDP_PASS     = 2,
    XDP_TX       = 3,
    XDP_REDIRECT = 4
};

static constexpr uint16_t ETH_P_IP        = 0x0800;
static constexpr uint16_t ETH_P_8021Q     = 0x8100;
static constexpr uint8_t  IPPROTO_ICMP    = 1;
static constexpr uint8_t  IPPROTO_TCP     = 6;
static constexpr uint8_t  IPPROTO_UDP     = 17;

static constexpr uint8_t  TCP_FLAG_FIN    = 0x01;
static constexpr uint8_t  TCP_FLAG_SYN    = 0x02;
static constexpr uint8_t  TCP_FLAG_RST    = 0x04;
static constexpr uint8_t  TCP_FLAG_ACK    = 0x10;

static constexpr int      MAX_PACKET_LEN  = 1518;
static constexpr int      BLOCKLIST_SIZE  = 16;
static constexpr int      BUCKET_COUNT    = 64;
static constexpr int      MAX_VLAN_TAGS   = 2;

// -----------------------------------------------------------------------------
// Verifier-Safe Packed Wire Headers & Per-CPU Map State
// -----------------------------------------------------------------------------

struct EthHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype_be;
};

struct Ipv4Header {
    uint8_t  ver_ihl;       // version (4b) + header length in 32-bit words (4b)
    uint8_t  tos;
    uint16_t total_len_be;
    uint16_t id_be;
    uint16_t frag_off_be;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum_be;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct L4Header {
    uint16_t src_port_be;
    uint16_t dst_port_be;
    uint32_t seq_or_len;
    uint32_t ack_or_csum;
    uint8_t  data_off;
    uint8_t  tcp_flags;
    uint16_t window_be;
};

struct ParsedFlow {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  tcp_flags;
    uint16_t payload_len;
    uint32_t flow_hash;
    bool     bounds_valid;
};

struct CidrBlockRule {
    uint32_t network;
    uint32_t mask;
    uint32_t hit_count;
    uint8_t  severity;      // 1 = rate-limit, 2 = hard XDP_DROP
    uint8_t  active;
};

struct TokenBucket {
    uint64_t tokens;
    uint64_t last_ns;
    uint64_t dropped_pkts;
    uint64_t passed_pkts;
};

struct XdpControlPlane {
    std::array<CidrBlockRule, BLOCKLIST_SIZE> blocklist;
    std::array<TokenBucket, BUCKET_COUNT>     buckets;
    std::atomic<uint64_t>                     syn_flood_counter;
    uint64_t                                  syn_threshold_pps;
    uint64_t                                  rx_total;
    uint64_t                                  tx_drop_total;
    uint64_t                                  tx_pass_total;
    uint64_t                                  verifier_bounds_rejects;
};

static XdpControlPlane g_xdp_state;

// Helper: big-endian 16-bit read (portable, zero unaligned UB)
static inline uint16_t read_be16(const uint8_t* ptr) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(ptr[0]) << 8) |
                                 static_cast<uint16_t>(ptr[1]));
}

// Helper: big-endian 32-bit read
static inline uint32_t read_be32(const uint8_t* ptr) noexcept {
    return (static_cast<uint32_t>(ptr[0]) << 24) |
           (static_cast<uint32_t>(ptr[1]) << 16) |
           (static_cast<uint32_t>(ptr[2]) << 8)  |
           static_cast<uint32_t>(ptr[3]);
}

// -----------------------------------------------------------------------------
// HOT PATH FUNCTIONS — Kernel XDP Packet Processing (<100ns per packet)
// -----------------------------------------------------------------------------

/**
 * compute_flow_tuple_hash — CLEAN HOT PATH
 * Deterministic 5-tuple packet hash used to index per-CPU rate-limiter maps.
 * Pure register arithmetic: ideal target for sroa, mem2reg, instcombine.
 */
[[hft::hot]]
uint32_t compute_flow_tuple_hash(uint32_t src_ip,
                                 uint32_t dst_ip,
                                 uint16_t src_port,
                                 uint16_t dst_port,
                                 uint8_t  protocol) noexcept
{
    uint32_t h = 0x811C9DC5u;
    h ^= src_ip;
    h *= 0x01000193u;
    h ^= dst_ip;
    h *= 0x01000193u;
    uint32_t ports = (static_cast<uint32_t>(src_port) << 16) | static_cast<uint32_t>(dst_port);
    h ^= ports;
    h *= 0x01000193u;
    h ^= static_cast<uint32_t>(protocol);
    h *= 0x01000193u;
    h ^= (h >> 16);
    return h;
}

/**
 * parse_ethernet_ipv4_hdr — Verifier-Safe Explicit Pointer Bounds Checking
 * Every byte access is guarded by `(cursor + needed <= data_end)` so the Linux
 * kernel verifier can statically prove zero out-of-bounds kernel reads.
 */
[[hft::hot]]
ParsedFlow parse_ethernet_ipv4_hdr(const uint8_t* data, const uint8_t* data_end) noexcept
{
    ParsedFlow flow{};
    flow.bounds_valid = false;

    if (!data || !data_end || data_end < data) {
        return flow;
    }

    const uint8_t* cursor = data;

    // 1. Ethernet header bounds guard (14 bytes)
    if (static_cast<size_t>(data_end - cursor) < 14u) {
        return flow;
    }
    uint16_t ethertype = read_be16(cursor + 12);
    cursor += 14;

    // Bounded VLAN tag peel (verifier forbids unbounded while-loops)
    for (int v = 0; v < MAX_VLAN_TAGS; ++v) {
        if (ethertype != ETH_P_8021Q) {
            break;
        }
        if (static_cast<size_t>(data_end - cursor) < 4u) {
            return flow;
        }
        ethertype = read_be16(cursor + 2);
        cursor += 4;
    }

    if (ethertype != ETH_P_IP) {
        return flow;
    }

    // 2. IPv4 minimum header bounds guard (20 bytes)
    if (static_cast<size_t>(data_end - cursor) < 20u) {
        return flow;
    }
    uint8_t ver_ihl = cursor[0];
    uint8_t ip_ver  = (ver_ihl >> 4) & 0x0Fu;
    uint8_t ihl_len = static_cast<uint8_t>((ver_ihl & 0x0Fu) * 4u);
    if (ip_ver != 4u || ihl_len < 20u) {
        return flow;
    }
    if (static_cast<size_t>(data_end - cursor) < ihl_len) {
        return flow;
    }

    flow.protocol = cursor[9];
    flow.src_ip   = read_be32(cursor + 12);
    flow.dst_ip   = read_be32(cursor + 16);
    uint16_t ip_total_len = read_be16(cursor + 2);
    cursor += ihl_len;

    // 3. L4 TCP/UDP bounds guard (minimum 8 bytes for ports + header info)
    if (flow.protocol == IPPROTO_TCP) {
        if (static_cast<size_t>(data_end - cursor) < 14u) {
            return flow;
        }
        flow.src_port  = read_be16(cursor);
        flow.dst_port  = read_be16(cursor + 2);
        flow.tcp_flags = cursor[13];
        flow.payload_len = (ip_total_len > ihl_len + 20u)
                               ? static_cast<uint16_t>(ip_total_len - ihl_len - 20u)
                               : 0u;
    } else if (flow.protocol == IPPROTO_UDP) {
        if (static_cast<size_t>(data_end - cursor) < 8u) {
            return flow;
        }
        flow.src_port    = read_be16(cursor);
        flow.dst_port    = read_be16(cursor + 2);
        uint16_t udp_len = read_be16(cursor + 4);
        flow.payload_len = (udp_len >= 8u) ? static_cast<uint16_t>(udp_len - 8u) : 0u;
    } else {
        flow.src_port    = 0;
        flow.dst_port    = 0;
        flow.payload_len = 0;
    }

    flow.flow_hash = compute_flow_tuple_hash(
        flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol);
    flow.bounds_valid = true;
    return flow;
}

/**
 * check_ip_blocklist_lpm — Constant-Bound CIDR Prefix Table Scan
 * Unrolled / vectorized by HWTuner (`loop-vectorize` + `slp-vectorizer`)
 * while preserving exact fixed loop count `BLOCKLIST_SIZE`.
 */
[[hft::hot]]
int check_ip_blocklist_lpm(uint32_t src_ip) noexcept
{
    int action = 0;
    for (int i = 0; i < BLOCKLIST_SIZE; ++i) {
        const CidrBlockRule& rule = g_xdp_state.blocklist[i];
        if (rule.active != 0u && ((src_ip & rule.mask) == rule.network)) {
            if (static_cast<int>(rule.severity) > action) {
                action = static_cast<int>(rule.severity);
            }
        }
    }
    return action;
}

/**
 * classify_syn_flood — Deliberate LAP-007 (seq_cst atomic) + LAP-010 (branch-heavy)
 * Demonstrates Fixer Agent flagging cross-CPU atomic lock contention & deep
 * branch chains that hurt XDP p99 tail latency during volumetric SYN attacks.
 */
[[hft::hot]]
int classify_syn_flood(const ParsedFlow& flow) noexcept
{
    if (flow.protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // ❌ LAP-007: default memory_order_seq_cst atomic RMW causes bus lock across NUMA cores
    uint64_t syns = g_xdp_state.syn_flood_counter.load(std::memory_order_seq_cst);

    bool is_pure_syn = ((flow.tcp_flags & TCP_FLAG_SYN) != 0) &&
                       ((flow.tcp_flags & TCP_FLAG_ACK) == 0);

    // ❌ LAP-010: deeply nested port/flag classification branches cause mispredictions
    if (is_pure_syn) {
        syns = g_xdp_state.syn_flood_counter.fetch_add(1u) + 1u;
        if (flow.dst_port == 443 || flow.dst_port == 80) {
            if (syns > g_xdp_state.syn_threshold_pps) {
                if (flow.src_port < 1024u) {
                    return XDP_DROP;  // Privileged source port SYN spoof under flood
                } else if (flow.payload_len > 64u) {
                    return XDP_DROP;  // Abnormal SYN payload flood
                } else {
                    return XDP_DROP;  // Rate exceeded — drop before sk_buff allocation
                }
            }
        } else if (flow.dst_port == 22 || flow.dst_port == 3389) {
            if (syns > (g_xdp_state.syn_threshold_pps / 2u)) {
                return XDP_DROP;
            }
        } else {
            if ((flow.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0) {
                return XDP_DROP;      // Malformed XMAS / SYN+FIN / SYN+RST scan
            }
        }
    }
    return XDP_PASS;
}

/**
 * inspect_udp_amplification — Deliberate LAP-006 (indirect std::function call)
 * Blocks DNS (53), NTP monlist (123), Memcached (11211), and SSDP (1900) reflection.
 * Indirect std::function triggers Fixer Agent to advise direct inlined calls,
 * which eBPF's verifier strongly prefers over indirect tail/helper dispatch.
 */
[[hft::hot]]
int inspect_udp_amplification(const ParsedFlow& flow) noexcept
{
    if (flow.protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // ❌ LAP-006: std::function prevents aggressive inlining in kernel path
    std::function<bool(uint16_t, uint16_t)> is_reflection_vector =
        [](uint16_t sport, uint16_t pay_len) -> bool {
            if (sport == 11211u && pay_len > 16u) return true; // Memcached amp
            if (sport == 123u   && pay_len > 48u) return true; // NTP monlist amp
            if (sport == 53u    && pay_len > 512u)return true; // DNS ANY amp
            if (sport == 1900u  && pay_len > 64u) return true; // SSDP reflection
            return false;
        };

    if (is_reflection_vector(flow.src_port, flow.payload_len)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

/**
 * update_token_bucket — Per-Flow Rate Limiter (Verifier-Safe Masked Index)
 * Uses bitmask `& (BUCKET_COUNT - 1)` so index is statically bounded [0, 63].
 */
[[hft::hot]]
int update_token_bucket(uint32_t flow_hash, uint64_t now_ns) noexcept
{
    uint32_t idx = flow_hash & static_cast<uint32_t>(BUCKET_COUNT - 1);
    TokenBucket& bucket = g_xdp_state.buckets[idx];

    uint64_t elapsed_us = (now_ns > bucket.last_ns) ? ((now_ns - bucket.last_ns) / 1000ULL) : 0ULL;
    uint64_t refill = elapsed_us * 2ULL;
    if (refill > 0ULL) {
        uint64_t updated = bucket.tokens + refill;
        bucket.tokens  = (updated > 100ULL) ? 100ULL : updated;
        bucket.last_ns = now_ns;
    }

    if (bucket.tokens == 0ULL) {
        bucket.dropped_pkts += 1ULL;
        return XDP_DROP;
    }
    bucket.tokens -= 1ULL;
    bucket.passed_pkts += 1ULL;
    return XDP_PASS;
}

/**
 * on_xdp_rx_packet — Top-Level Edge Packet Ingress Filter (Tick-to-Verdict)
 * Coordinates L2-L4 bounds parsing, CIDR blocklist, SYN flood defense,
 * UDP amplification filtering, and token-bucket rate shaping.
 */
[[hft::hot]]
int on_xdp_rx_packet(const uint8_t* data, const uint8_t* data_end, uint64_t now_ns) noexcept
{
    g_xdp_state.rx_total += 1ULL;

    ParsedFlow flow = parse_ethernet_ipv4_hdr(data, data_end);
    if (!flow.bounds_valid) {
        g_xdp_state.verifier_bounds_rejects += 1ULL;
        g_xdp_state.tx_drop_total += 1ULL;
        return XDP_DROP;
    }

    // 1. Check hard CIDR blocklist (botnet / spoofed prefixes)
    int rule_sev = check_ip_blocklist_lpm(flow.src_ip);
    if (rule_sev >= 2) {
        g_xdp_state.tx_drop_total += 1ULL;
        return XDP_DROP;
    }

    // 2. SYN flood detector
    if (classify_syn_flood(flow) == XDP_DROP) {
        g_xdp_state.tx_drop_total += 1ULL;
        return XDP_DROP;
    }

    // 3. UDP reflection / amplification blocker
    if (inspect_udp_amplification(flow) == XDP_DROP) {
        g_xdp_state.tx_drop_total += 1ULL;
        return XDP_DROP;
    }

    // 4. Token-bucket shaper for graylisted or bursty flows
    if (rule_sev == 1 || flow.protocol == IPPROTO_ICMP) {
        if (update_token_bucket(flow.flow_hash, now_ns) == XDP_DROP) {
            g_xdp_state.tx_drop_total += 1ULL;
            return XDP_DROP;
        }
    }

    g_xdp_state.tx_pass_total += 1ULL;
    return XDP_PASS;
}

// -----------------------------------------------------------------------------
// COLD PATH DECLARATIONS (Definitions placed after main to keep L1i clean)
// -----------------------------------------------------------------------------

[[hft::cold]]
void load_acl_rules(uint64_t syn_threshold);

[[hft::cold]]
void flush_xdp_ring_metrics();

[[hft::cold]]
std::string generate_mitigation_report();

// Helper for building synthetic Ethernet+IPv4+L4 wire packets in tests
static int build_synthetic_packet(uint8_t* buf,
                                    uint32_t src_ip,
                                    uint32_t dst_ip,
                                    uint8_t  proto,
                                    uint16_t src_port,
                                    uint16_t dst_port,
                                    uint8_t  tcp_flags,
                                    uint16_t payload_len)
{
    int idx = 0;
    for (int i = 0; i < 12; ++i) buf[idx++] = 0xAA;
    buf[idx++] = 0x08; buf[idx++] = 0x00; // ETH_P_IP

    // IPv4 Header (20 bytes)
    uint16_t total_len = static_cast<uint16_t>(20 + 20 + payload_len);
    buf[idx++] = 0x45; // v4, IHL=5 (20B)
    buf[idx++] = 0x00;
    buf[idx++] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
    buf[idx++] = static_cast<uint8_t>(total_len & 0xFF);
    buf[idx++] = 0x12; buf[idx++] = 0x34;
    buf[idx++] = 0x40; buf[idx++] = 0x00;
    buf[idx++] = 64;   // TTL
    buf[idx++] = proto;
    buf[idx++] = 0x00; buf[idx++] = 0x00;
    buf[idx++] = static_cast<uint8_t>((src_ip >> 24) & 0xFF);
    buf[idx++] = static_cast<uint8_t>((src_ip >> 16) & 0xFF);
    buf[idx++] = static_cast<uint8_t>((src_ip >> 8)  & 0xFF);
    buf[idx++] = static_cast<uint8_t>(src_ip & 0xFF);
    buf[idx++] = static_cast<uint8_t>((dst_ip >> 24) & 0xFF);
    buf[idx++] = static_cast<uint8_t>((dst_ip >> 16) & 0xFF);
    buf[idx++] = static_cast<uint8_t>((dst_ip >> 8)  & 0xFF);
    buf[idx++] = static_cast<uint8_t>(dst_ip & 0xFF);

    // L4 Header (20 bytes)
    buf[idx++] = static_cast<uint8_t>((src_port >> 8) & 0xFF);
    buf[idx++] = static_cast<uint8_t>(src_port & 0xFF);
    buf[idx++] = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
    buf[idx++] = static_cast<uint8_t>(dst_port & 0xFF);
    uint16_t l4_len = static_cast<uint16_t>(8 + payload_len);
    buf[idx++] = 0x00; buf[idx++] = static_cast<uint8_t>(l4_len & 0xFF);
    buf[idx++] = 0x00; buf[idx++] = 0x00;
    buf[idx++] = 0x00; buf[idx++] = 0x00;
    buf[idx++] = 0x00; buf[idx++] = 0x00;
    buf[idx++] = 0x50;
    buf[idx++] = tcp_flags;
    buf[idx++] = 0x20; buf[idx++] = 0x00;
    for (int i = 0; i < 4; ++i) buf[idx++] = 0x00;
    return idx;
}

// -----------------------------------------------------------------------------
// Main Entrypoint — Simulates 6-Packet Edge Burst + Differential Edge Fixtures
// -----------------------------------------------------------------------------

int main()
{
    uint64_t syn_limit = 2ULL;
    char line[128] = {0};
    if (std::fgets(line, sizeof(line), stdin) != nullptr && line[0] != '\0') {
        long parsed = std::strtol(line, nullptr, 10);
        if (parsed > 0 && parsed < 1000000L) {
            syn_limit = static_cast<uint64_t>(parsed);
        }
    }

    load_acl_rules(syn_limit);

    uint8_t pkt[128] = {0};
    uint64_t t0 = 1700000000000ULL;

    // Packet 1: Legitimate TLS client HTTPS request -> XDP_PASS
    int n1 = build_synthetic_packet(pkt, 0x0A000105u, 0xC6336401u, IPPROTO_TCP, 51234, 443, TCP_FLAG_SYN, 0);
    on_xdp_rx_packet(pkt, pkt + n1, t0 + 1000ULL);

    // Packet 2: Known botnet CIDR prefix (203.0.113.0/24) -> XDP_DROP
    int n2 = build_synthetic_packet(pkt, 0xCB00712Au, 0xC6336401u, IPPROTO_TCP, 44444, 443, TCP_FLAG_SYN, 0);
    on_xdp_rx_packet(pkt, pkt + n2, t0 + 2000ULL);

    // Packet 3: Memcached UDP amplification payload (sport=11211, len=256) -> XDP_DROP
    int n3 = build_synthetic_packet(pkt, 0x01010101u, 0xC6336401u, IPPROTO_UDP, 11211, 50000, 0, 256);
    on_xdp_rx_packet(pkt, pkt + n3, t0 + 3000ULL);

    // Packet 4: Truncated malformed packet (fails XDP bounds check) -> XDP_DROP
    on_xdp_rx_packet(pkt, pkt + 18, t0 + 4000ULL);

    // Packet 5 & 6: SYN flood burst crossing configured threshold
    int n5 = build_synthetic_packet(pkt, 0x0A000210u, 0xC6336401u, IPPROTO_TCP, 55001, 443, TCP_FLAG_SYN, 0);
    on_xdp_rx_packet(pkt, pkt + n5, t0 + 5000ULL);
    on_xdp_rx_packet(pkt, pkt + n5, t0 + 6000ULL);

    flush_xdp_ring_metrics();
    return 0;
}

// -----------------------------------------------------------------------------
// COLD PATH IMPLEMENTATIONS — Control Plane Setup, Logging & Telemetry
// -----------------------------------------------------------------------------

[[hft::cold]]
void load_acl_rules(uint64_t syn_threshold)
{
    for (int i = 0; i < BLOCKLIST_SIZE; ++i) {
        g_xdp_state.blocklist[i] = {0u, 0u, 0u, 0u, 0u};
    }
    for (int i = 0; i < BUCKET_COUNT; ++i) {
        g_xdp_state.buckets[i] = {10ULL, 0ULL, 0ULL, 0ULL};
    }

    // Rule 0: Hard drop botnet subnet 203.0.113.0/24
    g_xdp_state.blocklist[0] = {0xCB007100u, 0xFFFFFF00u, 0u, 2u, 1u};
    // Rule 1: Hard drop bogon/unroutable source 198.51.100.0/24
    g_xdp_state.blocklist[1] = {0xC6336400u, 0xFFFFFF00u, 0u, 2u, 1u};
    // Rule 2: Rate-limit suspicious scanner subnet 192.0.2.0/24
    g_xdp_state.blocklist[2] = {0xC0000200u, 0xFFFFFF00u, 0u, 1u, 1u};

    g_xdp_state.syn_flood_counter.store(0ULL, std::memory_order_relaxed);
    g_xdp_state.syn_threshold_pps       = syn_threshold;
    g_xdp_state.rx_total                = 0ULL;
    g_xdp_state.tx_drop_total           = 0ULL;
    g_xdp_state.tx_pass_total           = 0ULL;
    g_xdp_state.verifier_bounds_rejects = 0ULL;
}

[[hft::cold]]
void flush_xdp_ring_metrics()
{
    std::printf(
        "[XDP-DDoS] RX=%llu | PASS=%llu | DROP=%llu | BoundsReject=%llu\n",
        static_cast<unsigned long long>(g_xdp_state.rx_total),
        static_cast<unsigned long long>(g_xdp_state.tx_pass_total),
        static_cast<unsigned long long>(g_xdp_state.tx_drop_total),
        static_cast<unsigned long long>(g_xdp_state.verifier_bounds_rejects));
}

[[hft::cold]]
std::string generate_mitigation_report()
{
    std::string out = "=== eBPF / XDP Edge Mitigation Report ===\n";
    out += "Total RX packets      : " + std::to_string(g_xdp_state.rx_total) + "\n";
    out += "Total XDP_PASS        : " + std::to_string(g_xdp_state.tx_pass_total) + "\n";
    out += "Total XDP_DROP        : " + std::to_string(g_xdp_state.tx_drop_total) + "\n";
    out += "Bounds check drops    : " + std::to_string(g_xdp_state.verifier_bounds_rejects) + "\n";
    out += "SYN flood counter     : " + std::to_string(g_xdp_state.syn_flood_counter.load()) + "\n";
    return out;
}

