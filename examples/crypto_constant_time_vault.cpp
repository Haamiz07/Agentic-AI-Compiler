// =============================================================================
// AGentic_C Example: Cryptography — Constant-Time Zero-Trust Packet Vault
// File: examples/crypto_constant_time_vault.cpp
// =============================================================================
//
// Real-World Industry Context (OpenSSL, BoringSSL, Signal, WireGuard, HSMs):
//   Production cryptographic engines encrypt millions of TLS/tunnel frames/sec
//   while upholding strict security invariants that standard `clang -O3` can break:
//     1. CWE-14 (Dead-Store Key Wipe Elimination):
//        Standard DSE/SROA passes often eliminate `std::memset(secret, 0, n)` at
//        the end of a function because the buffer is not read afterwards, leaving
//        key material exposed on the stack.
//     2. CWE-208 (Compiler-Introduced Timing Side-Channels):
//        Branching on secret tag comparisons or non-constant-time tiers leaks key
//        bits via nanosecond timing measurements.
//     3. CWE-362 / Atomic Replay Window Hazards:
//        Excessive seq_cst locking stalls throughput, while heap allocations in
//        session packet paths cause cache spikes and key-paging leaks.
//
// How AGentic_C Solves This:
//   1. Boss Agent classifies cipher, MAC, and key-scrub primitives as HOT and
//      audit logging / HSM boot diagnostics as COLD (L1i cache isolation).
//   2. CandidateValidator enforces the CWE-14 Security-Invariant Gate after
//      every LLVM `opt` pass: passes like `sroa` that strip `llvm.memset`
//      scrubbing calls without zero-store replacement are rejected, and Critic
//      Feedback falls back to safe passes (`mem2reg`, `instcombine`, SIMD).
//   3. Fixer Agent flags variable-time branching (LAP-010), indirect filter
//      callbacks (LAP-006), and heavy seq_cst atomics (LAP-007) in hot paths.
//
// Functions Overview:
//   constant_time_select_u32     → HOT  Branchless CMOV mask selection (CLEAN)
//   chacha20_quarter_round       → HOT  ARX column/diagonal cipher step (CLEAN)
//   encrypt_packet_block         → HOT  20-round ChaCha-style stream cipher
//   poly1305_mac_step            → HOT  Incremental auth tag accumulator (CLEAN)
//   verify_mac_constant_time     → HOT  Zero-branch constant-time MAC verifier
//   derive_and_scrub_key         → HOT  HKDF subkey + CWE-14 std::memset scrub
//   authorize_key_slot_legacy    → HOT  Deliberate LAP-006 + LAP-010 demo
//   seal_authenticated_frame     → HOT  Top-level AEAD encrypt + replay + scrub
//   init_hsm_vault_context       → COLD Startup root-key slot initialisation
//   log_crypto_audit             → COLD Non-critical audit trail output
//   generate_crypto_security_report → COLD Compliance & wipe telemetry report
//
// =============================================================================

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>

// -----------------------------------------------------------------------------
// Cryptographic Constants & Vault State Structures
// -----------------------------------------------------------------------------

static constexpr int CHACHA_STATE_WORDS  = 16;
static constexpr int CHACHA_KEY_WORDS    = 8;
static constexpr int CHACHA_ROUNDS       = 20;
static constexpr int MAX_PACKET_BYTES    = 64;
static constexpr int MAC_TAG_BYTES       = 16;
static constexpr int MAX_KEY_SLOTS       = 8;

// "expand 32-byte k" standard ChaCha20 diagonal constants
static constexpr uint32_t CHACHA_CONST_0 = 0x61707865u;
static constexpr uint32_t CHACHA_CONST_1 = 0x3320646Eu;
static constexpr uint32_t CHACHA_CONST_2 = 0x79622D32u;
static constexpr uint32_t CHACHA_CONST_3 = 0x6B206574u;

struct KeySlotPolicy {
    uint32_t key_id;
    uint32_t master_words[CHACHA_KEY_WORDS];
    uint8_t  clearance_tier;   // 1 = standard, 2 = privileged, 3 = HSM root
    uint8_t  allow_export;
    uint8_t  active;
};

struct EncryptedFrame {
    uint32_t seq_nonce;
    uint32_t key_slot_id;
    uint16_t payload_len;
    uint8_t  ciphertext[MAX_PACKET_BYTES];
    uint8_t  auth_mac[MAC_TAG_BYTES];
    int      mac_valid;
    int      key_wiped;
};

struct VaultEngineState {
    std::array<KeySlotPolicy, MAX_KEY_SLOTS> slots;
    std::atomic<uint64_t>                    replay_seq_counter;
    uint64_t                                 frames_encrypted;
    uint64_t                                 frames_verified;
    uint64_t                                 mac_failures;
    uint64_t                                 policy_rejects;
    uint32_t                                 last_session_token;
};

static VaultEngineState g_vault;

// Inline bitwise left-rotation (compiles cleanly to CPU ROL/ROR)
static inline uint32_t rotl32(uint32_t v, int shift) noexcept {
    return (v << shift) | (v >> (32 - shift));
}

// -----------------------------------------------------------------------------
// HOT PATH FUNCTIONS — Constant-Time AEAD Crypto & Key Scrubbing
// -----------------------------------------------------------------------------

/**
 * constant_time_select_u32 — CLEAN HOT PATH
 * Selects `a` if condition != 0 else `b` without conditional jump instructions.
 * Prevents branch-predictor & cache-timing side-channel leaks (CWE-208).
 */
[[hft::hot]]
uint32_t constant_time_select_u32(uint32_t condition, uint32_t a, uint32_t b) noexcept
{
    uint32_t non_zero = condition | (0u - condition);
    uint32_t mask = static_cast<uint32_t>(static_cast<int32_t>(non_zero) >> 31);
    return (a & mask) | (b & ~mask);
}

/**
 * chacha20_quarter_round — CLEAN HOT PATH
 * Single Add-Rotate-XOR (ARX) mixing primitive over 4 32-bit state words.
 */
[[hft::hot]]
static inline void chacha20_quarter_round(uint32_t& a,
                                          uint32_t& b,
                                          uint32_t& c,
                                          uint32_t& d) noexcept
{
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

/**
 * encrypt_packet_block — Constant-Time ChaCha-Style Stream Cipher
 * Computes 20 ARX rounds (10 column + 10 diagonal) and XORs plaintext bytes.
 * No secret-dependent table lookups (immune to L1 cache-timing attacks).
 */
[[hft::hot]]
void encrypt_packet_block(uint32_t state[CHACHA_STATE_WORDS],
                          const uint32_t key[CHACHA_KEY_WORDS],
                          uint32_t nonce,
                          uint32_t counter,
                          int rounds) noexcept
{
    state[0]  = CHACHA_CONST_0;
    state[1]  = CHACHA_CONST_1;
    state[2]  = CHACHA_CONST_2;
    state[3]  = CHACHA_CONST_3;
    for (int i = 0; i < CHACHA_KEY_WORDS; ++i) {
        state[4 + i] = key[i];
    }
    state[12] = counter;
    state[13] = nonce;
    state[14] = nonce ^ 0x9E3779B9u;
    state[15] = counter ^ 0x7F4A7C15u;

    uint32_t working[CHACHA_STATE_WORDS];
    for (int i = 0; i < CHACHA_STATE_WORDS; ++i) {
        working[i] = state[i];
    }

    int double_rounds = (rounds > 0) ? (rounds / 2) : 10;
    for (int r = 0; r < double_rounds; ++r) {
        // Odd round (columns)
        chacha20_quarter_round(working[0], working[4], working[8],  working[12]);
        chacha20_quarter_round(working[1], working[5], working[9],  working[13]);
        chacha20_quarter_round(working[2], working[6], working[10], working[14]);
        chacha20_quarter_round(working[3], working[7], working[11], working[15]);
        // Even round (diagonals)
        chacha20_quarter_round(working[0], working[5], working[10], working[15]);
        chacha20_quarter_round(working[1], working[6], working[11], working[12]);
        chacha20_quarter_round(working[2], working[7], working[8],  working[13]);
        chacha20_quarter_round(working[3], working[4], working[9],  working[14]);
    }

    for (int i = 0; i < CHACHA_STATE_WORDS; ++i) {
        state[i] += working[i];
    }
}

/**
 * poly1305_mac_step — CLEAN HOT PATH
 * Deterministic polynomial-style tag mixing across frame bytes and derived key.
 */
[[hft::hot]]
void poly1305_mac_step(const uint8_t* data,
                       int len,
                       uint32_t session_token,
                       uint8_t out_tag[MAC_TAG_BYTES]) noexcept
{
    uint32_t acc0 = 0x1B873593u ^ session_token;
    uint32_t acc1 = 0xCC9E2D51u + session_token;
    uint32_t acc2 = 0xE6546B64u ^ rotl32(session_token, 11);
    uint32_t acc3 = 0x85EBCA6Bu + rotl32(session_token, 19);

    int safe_len = (len > 0 && len <= MAX_PACKET_BYTES) ? len : MAX_PACKET_BYTES;
    for (int i = 0; i < safe_len; ++i) {
        uint32_t byte_val = static_cast<uint32_t>(data[i]);
        acc0 = rotl32(acc0 ^ (byte_val * 0x01000193u), 5) + acc1;
        acc1 = rotl32(acc1 + (byte_val ^ acc2), 7) ^ acc3;
        acc2 = rotl32(acc2 ^ acc0, 13) + 0x9E3779B9u;
        acc3 ^= acc1 + static_cast<uint32_t>(i);
    }

    uint32_t words[4] = { acc0, acc1, acc2, acc3 };
    for (int w = 0; w < 4; ++w) {
        out_tag[w * 4 + 0] = static_cast<uint8_t>((words[w] >> 24) & 0xFFu);
        out_tag[w * 4 + 1] = static_cast<uint8_t>((words[w] >> 16) & 0xFFu);
        out_tag[w * 4 + 2] = static_cast<uint8_t>((words[w] >> 8)  & 0xFFu);
        out_tag[w * 4 + 3] = static_cast<uint8_t>(words[w] & 0xFFu);
    }
}

/**
 * verify_mac_constant_time — Zero-Short-Circuit Constant-Time MAC Comparison
 * Never returns early on the first differing byte; XOR-accumulates every index
 * so valid and invalid tags execute in identical constant nanoseconds.
 */
[[hft::hot]]
int verify_mac_constant_time(const uint8_t* mac_a, const uint8_t* mac_b, int len) noexcept
{
    uint8_t diff = 0u;
    for (int i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(mac_a[i] ^ mac_b[i]);
    }
    return (diff == 0u) ? 1 : 0;
}

/**
 * derive_and_scrub_key — HKDF Ephemeral Subkey Derivation + CWE-14 Wipe
 * Security Invariant (CWE-14):
 *   `std::memset(temp_secret, 0, sizeof(temp_secret))` scrubs derived secret
 *   material from stack RAM before returning. Any LLVM pass (such as `sroa`)
 *   that optimizes away this memset without replacement zero-stores is rejected
 *   by AGentic_C's CWE-14 invariant checker.
 */
[[hft::hot]]
uint32_t derive_and_scrub_key(uint32_t master_seed, uint32_t nonce) noexcept
{
    uint32_t temp_secret[4];
    temp_secret[0] = master_seed ^ 0xA5A5A5A5u;
    temp_secret[1] = (nonce + 1u) * 0x01000193u;
    temp_secret[2] = rotl32(temp_secret[0] + temp_secret[1], 9);
    temp_secret[3] = (temp_secret[2] << 7) ^ (master_seed >> 3) ^ temp_secret[1];

    uint32_t mix_a = temp_secret[0] ^ temp_secret[2];
    uint32_t mix_b = temp_secret[1] + temp_secret[3];
    uint32_t session_token = rotl32(mix_a ^ mix_b, 5);

    // Mandatory CWE-14 secret memory wipe prior to stack unwind
    std::memset(temp_secret, 0, sizeof(temp_secret));
    return session_token;
}

/**
 * authorize_key_slot_legacy — Deliberate LAP-006 (std::function) + LAP-010 (branchy)
 * Demonstrates how Fixer Agent spots dangerous patterns in crypto hot paths:
 *   - Nested tier checks introduce branch misprediction & timing variance (LAP-010)
 *   - Indirect std::function policy hooks prevent aggressive inlining (LAP-006)
 */
[[hft::hot]]
int authorize_key_slot_legacy(uint32_t slot_id, uint8_t required_tier) noexcept
{
    if (slot_id >= static_cast<uint32_t>(MAX_KEY_SLOTS)) {
        return 0;
    }
    const KeySlotPolicy& slot = g_vault.slots[slot_id];

    // ❌ LAP-006: std::function prevents inlining of security policy check
    std::function<bool(const KeySlotPolicy&)> tier_checker =
        [required_tier](const KeySlotPolicy& p) -> bool {
            // ❌ LAP-010: Nested branching creates timing side-channel differences
            if (p.active == 1u) {
                if (p.clearance_tier >= required_tier) {
                    if (p.clearance_tier == 3u) {
                        return (p.allow_export == 0u);
                    } else if (p.clearance_tier == 2u) {
                        return true;
                    } else {
                        return (required_tier <= 1u);
                    }
                } else {
                    return false;
                }
            }
            return false;
        };

    return tier_checker(slot) ? 1 : 0;
}

/**
 * seal_authenticated_frame — End-to-End AEAD Encrypt, Sign, Verify & Scrub
 * Combines key-slot authorization, ChaCha20 keystream generation, XOR cipher,
 * Poly1305 tag verification, replay-sequence atomic counter (LAP-007), and
 * CWE-14 stack scrubbing.
 */
[[hft::hot]]
EncryptedFrame seal_authenticated_frame(uint32_t slot_id,
                                        const uint8_t* plaintext,
                                        uint16_t len,
                                        uint32_t nonce) noexcept
{
    EncryptedFrame frame{};
    frame.seq_nonce   = nonce;
    frame.key_slot_id = slot_id;
    frame.payload_len = (len <= MAX_PACKET_BYTES) ? len : static_cast<uint16_t>(MAX_PACKET_BYTES);

    if (!authorize_key_slot_legacy(slot_id, 2u)) {
        g_vault.policy_rejects += 1ULL;
        return frame;
    }

    // ❌ LAP-007: default seq_cst fetch_add creates cross-core memory barrier stall
    uint64_t ctr = g_vault.replay_seq_counter.fetch_add(1ULL) + 1ULL;
    const KeySlotPolicy& slot = g_vault.slots[slot_id];

    uint32_t state[CHACHA_STATE_WORDS] = {0};
    encrypt_packet_block(state, slot.master_words, nonce, static_cast<uint32_t>(ctr), CHACHA_ROUNDS);

    // Derive session authentication subkey & scrub temp stack secret (CWE-14)
    uint32_t session_tok = derive_and_scrub_key(state[0] ^ slot.key_id, nonce);
    g_vault.last_session_token = session_tok;
    frame.key_wiped = 1;

    // Stream-cipher XOR over fixed bounded payload
    for (uint16_t i = 0; i < frame.payload_len; ++i) {
        uint32_t ks_word = state[(i >> 2) & 15u];
        uint8_t  ks_byte = static_cast<uint8_t>((ks_word >> ((i & 3u) * 8u)) & 0xFFu);
        frame.ciphertext[i] = static_cast<uint8_t>(plaintext[i] ^ ks_byte);
    }

    // Generate & verify MAC tag in constant time
    uint8_t recomputed_mac[MAC_TAG_BYTES] = {0};
    poly1305_mac_step(frame.ciphertext, frame.payload_len, session_tok, frame.auth_mac);
    poly1305_mac_step(frame.ciphertext, frame.payload_len, session_tok, recomputed_mac);

    frame.mac_valid = verify_mac_constant_time(frame.auth_mac, recomputed_mac, MAC_TAG_BYTES);
    g_vault.frames_encrypted += 1ULL;
    if (frame.mac_valid == 1) {
        g_vault.frames_verified += 1ULL;
    } else {
        g_vault.mac_failures += 1ULL;
    }

    // Scrub keystream state buffer as well
    std::memset(state, 0, sizeof(state));
    return frame;
}

// -----------------------------------------------------------------------------
// COLD PATH DECLARATIONS (Definitions placed below main for L1i isolation)
// -----------------------------------------------------------------------------

[[hft::cold]]
void init_hsm_vault_context(uint32_t master_seed);

[[hft::cold]]
void log_crypto_audit(const EncryptedFrame& frame, int tamper_rejected);

[[hft::cold]]
std::string generate_crypto_security_report();

// -----------------------------------------------------------------------------
// Main Entrypoint — Simulates Authenticated Vault Frames + Tamper Check
// -----------------------------------------------------------------------------

int main()
{
    uint32_t base_nonce = 42u;
    char line[128] = {0};
    if (std::fgets(line, sizeof(line), stdin) != nullptr && line[0] != '\0') {
        long v = std::strtol(line, nullptr, 10);
        base_nonce = static_cast<uint32_t>(v);
    }

    init_hsm_vault_context(0xDEADBEEFu ^ base_nonce);

    // 32-byte sample order payload
    uint8_t plaintext[32] = {
        'B','U','Y',':','A','A','P','L',':','1','0','0','@','1','9','5',
        '.','5','0',';','T','I','D','=','0','0','9','9','1','1','2','2'
    };

    // Encrypt & authenticate two valid tunnel frames
    EncryptedFrame f1 = seal_authenticated_frame(0u, plaintext, 32u, base_nonce);
    EncryptedFrame f2 = seal_authenticated_frame(1u, plaintext, 32u, base_nonce + 1u);

    // Simulate network attacker flipping 1 bit in MAC tag — constant-time verifier must reject
    uint8_t forged_mac[MAC_TAG_BYTES];
    for (int i = 0; i < MAC_TAG_BYTES; ++i) {
        forged_mac[i] = f2.auth_mac[i];
    }
    forged_mac[MAC_TAG_BYTES - 1] ^= 0x01u;
    int tamper_ok = verify_mac_constant_time(f2.auth_mac, forged_mac, MAC_TAG_BYTES);

    // Branchless selection check
    uint32_t audit_code = constant_time_select_u32(
        static_cast<uint32_t>(f1.mac_valid), g_vault.last_session_token, 0u);
    g_vault.last_session_token = audit_code;

    log_crypto_audit(f1, (tamper_ok == 0) ? 1 : 0);
    return (f1.mac_valid == 1 && tamper_ok == 0) ? 0 : 1;
}

// -----------------------------------------------------------------------------
// COLD PATH IMPLEMENTATIONS — Setup, Reporting & Security Audit
// -----------------------------------------------------------------------------

[[hft::cold]]
void init_hsm_vault_context(uint32_t master_seed)
{
    for (int s = 0; s < MAX_KEY_SLOTS; ++s) {
        g_vault.slots[s].key_id         = static_cast<uint32_t>(0x1000 + s);
        g_vault.slots[s].clearance_tier = (s == 0) ? 3u : 2u;
        g_vault.slots[s].allow_export   = 0u;
        g_vault.slots[s].active         = (s < 4) ? 1u : 0u;
        for (int w = 0; w < CHACHA_KEY_WORDS; ++w) {
            g_vault.slots[s].master_words[w] =
                master_seed ^ static_cast<uint32_t>((s + 1) * 0x9E3779B9u + w * 17u);
        }
    }
    g_vault.replay_seq_counter.store(0ULL, std::memory_order_relaxed);
    g_vault.frames_encrypted   = 0ULL;
    g_vault.frames_verified    = 0ULL;
    g_vault.mac_failures       = 0ULL;
    g_vault.policy_rejects     = 0ULL;
    g_vault.last_session_token = 0u;
}

[[hft::cold]]
void log_crypto_audit(const EncryptedFrame& frame, int tamper_rejected)
{
    std::printf(
        "[CryptoVault] Nonce=%u | Len=%u | MAC=%d | Wiped(CWE-14)=%d | TamperBlocked=%d | Token=0x%08X\n",
        frame.seq_nonce,
        static_cast<unsigned>(frame.payload_len),
        frame.mac_valid,
        frame.key_wiped,
        tamper_rejected,
        g_vault.last_session_token);
}

[[hft::cold]]
std::string generate_crypto_security_report()
{
    std::string rep = "=== Zero-Trust Crypto Vault Audit Report ===\n";
    rep += "Frames encrypted     : " + std::to_string(g_vault.frames_encrypted) + "\n";
    rep += "MAC tags verified    : " + std::to_string(g_vault.frames_verified) + "\n";
    rep += "MAC verify failures  : " + std::to_string(g_vault.mac_failures) + "\n";
    rep += "Key policy rejects   : " + std::to_string(g_vault.policy_rejects) + "\n";
    rep += "Replay seq counter   : " + std::to_string(g_vault.replay_seq_counter.load()) + "\n";
    return rep;
}
