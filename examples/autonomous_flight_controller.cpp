// =============================================================================
// AGentic_C Example: Autonomous Flight & Emergency Braking Control Loop
// File: examples/autonomous_flight_controller.cpp
// =============================================================================
//
// Real-World Industry Context (Avionics DO-178C / Automotive ISO 26262 ASIL-D):
//   Autonomous drones, eVTOL aircraft, and vehicle AEB (Autonomous Emergency
//   Braking) controllers execute hard real-time 1 kHz closed-loop pipelines:
//     Sensor Fusion (LiDAR + Baro + IMU) -> EKF State -> PID Actuator -> Safety Guard
//
// Why General `clang -O3` Compilers Are Risky Here:
//   1. Hard Real-Time Determinism & Jitter (p99):
//      Inlining heavy black-box telemetry logging or error strings into 1 kHz
//      loops bloats L1 instruction cache (>32 KB) and causes unpredictable stalls.
//   2. Undefined Behavior & Safety Envelope Erosion:
//      Safety standards forbid dynamic heap alloc (`new`), unbounded mutexes,
//      and branch-heavy transitions that stall pipeline speculation.
//   3. Lack of Certification Auditability:
//      Aviation/automotive assessors require per-pass verification logs and
//      edge-case fixture equivalence (0, negative velocity, extreme overflow).
//
// How AGentic_C Solves This:
//   1. Boss Agent isolates 1 kHz control functions (`HOT`, strict ns budget)
//      from telemetry & pre-flight calibration (`COLD`, advisory only).
//   2. Fixer Agent catches safety/latency violations (LAP-006 indirect terrain
//      hooks, LAP-007 seq_cst servo bus locks, LAP-010 branchy mode trees).
//   3. CandidateValidator verifies behavior preservation across 6 differential
//      edge-case fixtures and verifies `.text` fits cleanly inside 32 KB L1i.
//
// Functions Overview:
//   fuse_sensor_altitude       → HOT  8-tap LiDAR+IMU weighted FIR filter (SIMD)
//   kalman_predict_and_update  → HOT  1D EKF altitude + sink-rate estimator (CLEAN)
//   compute_pid_thrust         → HOT  Anti-windup branchless PID clamp (CLEAN)
//   check_collision_envelope   → HOT  ISO-26262 kinematic stopping guard (CLEAN)
//   select_flight_mode_legacy  → HOT  Deliberate LAP-006 + LAP-010 safety demo
//   actuate_redundant_servo_bus→ HOT  Deliberate LAP-007 dual-bus atomic publish
//   run_1khz_control_tick      → HOT  Top-level real-time closed-loop tick
//   calibrate_imu_preflight    → COLD Pre-flight gyro bias & covariance setup
//   record_flight_telemetry    → COLD Black-box cockpit telemetry logger
//   generate_blackbox_summary  → COLD Post-flight DO-178C safety audit dump
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
// Real-Time Avionics Constants & State Structures
// -----------------------------------------------------------------------------

static constexpr int   SENSOR_TAPS          = 8;
static constexpr float MIN_SAFE_DT_SEC      = 0.0001f;
static constexpr float MAX_DECEL_BRAKE_G    = 6.25f;   // 1 / (2 * a_max) scaled factor = 0.08
static constexpr float EMERGENCY_THRUST_MAX = 100.0f;
static constexpr float EMERGENCY_THRUST_MIN = 0.0f;

enum FlightMode : int {
    MODE_CRUISE          = 0,
    MODE_PRECISION_HOVER = 1,
    MODE_DESCENT_FLARE   = 2,
    MODE_ABORT_CLIMB     = 3,
    MODE_EMERGENCY_BRAKE = 4
};

struct EkfState {
    float altitude_m;
    float vertical_vel_mps;
    float p_alt;
    float p_vel;
    float accel_bias;
};

struct PidControllerState {
    float kp;
    float ki;
    float kd;
    float integral_error;
    float prev_error;
    float integral_limit;
};

struct ControlCommand {
    float fused_altitude_m;
    float estimated_vel_mps;
    float thrust_pct;
    int   flight_mode;
    int   safety_envelope_ok;
    int   emergency_override;
};

struct FlightControlSystem {
    EkfState                           ekf;
    PidControllerState                 pid;
    std::array<float, SENSOR_TAPS>     imu_weights;
    std::atomic<uint32_t>              actuator_pwm_bus;
    uint64_t                           tick_count;
    uint64_t                           envelope_interventions;
    float                              min_safe_margin_m;
    float                              target_altitude_m;
    float                              last_thrust_pct;
    int                                current_mode;
};

static FlightControlSystem g_fcs;

// -----------------------------------------------------------------------------
// HOT PATH FUNCTIONS — 1 kHz Hard Real-Time Sensor-to-Actuator Loop
// -----------------------------------------------------------------------------

/**
 * fuse_sensor_altitude — CLEAN HOT PATH (SIMD Vectorizable FIR Filter)
 * Combines multi-ray LiDAR returns with calibrated IMU confidence weights
 * using a fixed 8-tap loop ideal for LLVM `loop-vectorize` and `slp-vectorizer`.
 */
[[hft::hot]]
float fuse_sensor_altitude(const float* lidar_readings,
                           const float* imu_weights,
                           int count) noexcept
{
    int safe_count = (count > 0 && count <= SENSOR_TAPS) ? count : SENSOR_TAPS;
    float weighted_sum = 0.0f;
    float weight_norm  = 0.0f;

    for (int i = 0; i < safe_count; ++i) {
        float w = (imu_weights[i] >= 0.0f) ? imu_weights[i] : 0.0f;
        weighted_sum += lidar_readings[i] * w;
        weight_norm  += w;
    }

    float safe_norm = (weight_norm > 0.0001f) ? weight_norm : 1.0f;
    return weighted_sum / safe_norm;
}

/**
 * kalman_predict_and_update — CLEAN HOT PATH
 * Lightweight constant-time 1D Extended Kalman Filter updating vertical
 * altitude and velocity estimates from fused altitude measurements.
 */
[[hft::hot]]
void kalman_predict_and_update(EkfState& ekf,
                               float measured_alt_m,
                               float vertical_accel_mps2,
                               float dt_sec) noexcept
{
    float dt = (dt_sec > MIN_SAFE_DT_SEC) ? dt_sec : MIN_SAFE_DT_SEC;
    float corrected_accel = vertical_accel_mps2 - ekf.accel_bias;

    // 1. Time update (kinematic prediction)
    float pred_alt = ekf.altitude_m + ekf.vertical_vel_mps * dt + 0.5f * corrected_accel * dt * dt;
    float pred_vel = ekf.vertical_vel_mps + corrected_accel * dt;
    float pred_p   = ekf.p_alt + 0.02f;

    // 2. Measurement update (scalar Kalman gain)
    constexpr float meas_noise_r = 0.08f;
    float k_gain = pred_p / (pred_p + meas_noise_r);
    float innovation = measured_alt_m - pred_alt;

    ekf.altitude_m       = pred_alt + k_gain * innovation;
    ekf.vertical_vel_mps = pred_vel + (k_gain * innovation) * (0.25f / dt);
    ekf.p_alt            = (1.0f - k_gain) * pred_p;
}

/**
 * compute_pid_thrust — CLEAN HOT PATH
 * Branchless PID actuator controller with anti-windup integral clamping and
 * output saturation in [0.0%, 100.0%]. Avoids floating-point divide-by-zero.
 */
[[hft::hot]]
float compute_pid_thrust(float setpoint,
                         float measured,
                         PidControllerState& pid,
                         float dt) noexcept
{
    float safe_dt = (dt > MIN_SAFE_DT_SEC) ? dt : MIN_SAFE_DT_SEC;
    float error   = setpoint - measured;

    // Anti-windup bounded integral accumulation
    float next_int = pid.integral_error + error * safe_dt;
    float clamp_int_hi = (next_int >  pid.integral_limit) ?  pid.integral_limit : next_int;
    float clamp_int    = (clamp_int_hi < -pid.integral_limit) ? -pid.integral_limit : clamp_int_hi;
    pid.integral_error = clamp_int;

    float derivative = (error - pid.prev_error) / safe_dt;
    pid.prev_error   = error;

    float raw_thrust = (pid.kp * error) + (pid.ki * pid.integral_error) + (pid.kd * derivative) + 45.0f;

    // Branchless output saturation clamp [0.0f, 100.0f]
    float clamped_low  = (raw_thrust  < EMERGENCY_THRUST_MIN) ? EMERGENCY_THRUST_MIN : raw_thrust;
    float clamped_high = (clamped_low > EMERGENCY_THRUST_MAX) ? EMERGENCY_THRUST_MAX : clamped_low;
    return clamped_high;
}

/**
 * check_collision_envelope — CLEAN HOT PATH (ISO 26262 / DO-178C Guard)
 * Verifies kinematic stopping distance leaving at least `min_safe_dist_m`
 * ground/obstacle clearance even under full negative sink velocity.
 */
[[hft::hot]]
int check_collision_envelope(float distance_m,
                             float velocity_mps,
                             float min_safe_dist_m) noexcept
{
    float stopping_distance = (velocity_mps * velocity_mps) * 0.08f;
    return ((distance_m - stopping_distance) >= min_safe_dist_m) ? 1 : 0;
}

/**
 * select_flight_mode_legacy — Deliberate LAP-006 (std::function) + LAP-010 (branches)
 * Demonstrates Fixer Agent identifying non-deterministic branch trees and indirect
 * std::function policy dispatch inside real-time flight mode selection.
 */
[[hft::hot]]
int select_flight_mode_legacy(float alt_m,
                              float sink_rate_mps,
                              int   envelope_ok) noexcept
{
    // ❌ LAP-006: indirect std::function blocks deterministic timing inlining
    std::function<int(float, float, int)> mode_evaluator =
        [](float a, float v, int ok) -> int {
            // ❌ LAP-010: Deeply nested mode-switch tree hurts WCET predictability
            if (ok == 0) {
                if (a < 6.0f) {
                    return MODE_EMERGENCY_BRAKE;
                } else {
                    return MODE_ABORT_CLIMB;
                }
            } else {
                if (a < 2.5f) {
                    if (v < -1.5f) {
                        return MODE_DESCENT_FLARE;
                    } else {
                        return MODE_PRECISION_HOVER;
                    }
                } else if (a < 10.0f) {
                    return MODE_DESCENT_FLARE;
                } else {
                    return MODE_CRUISE;
                }
            }
        };

    return mode_evaluator(alt_m, sink_rate_mps, envelope_ok);
}

/**
 * actuate_redundant_servo_bus — Deliberate LAP-007 (seq_cst atomic stall)
 * Writes scaled 16-bit PWM thrust across dual avionics actuator channel.
 */
[[hft::hot]]
uint32_t actuate_redundant_servo_bus(float thrust_pct, int mode) noexcept
{
    uint32_t pwm_ticks = static_cast<uint32_t>(thrust_pct * 10.0f) + 1000u;
    uint32_t frame_word = ((static_cast<uint32_t>(mode) & 0xFu) << 16) | (pwm_ticks & 0xFFFFu);
    // ❌ LAP-007: memory_order_seq_cst store introduces full bus fence overhead
    g_fcs.actuator_pwm_bus.store(frame_word, std::memory_order_seq_cst);
    return frame_word;
}

/**
 * run_1khz_control_tick — Top-Level Real-Time Flight Control Cycle
 * Executes sensor fusion -> EKF update -> PID thrust -> collision guard -> servo output.
 */
[[hft::hot]]
ControlCommand run_1khz_control_tick(const float* lidar_readings,
                                     int          tap_count,
                                     float        vertical_accel,
                                     float        approach_speed,
                                     float        dt_sec) noexcept
{
    ControlCommand cmd{};
    g_fcs.tick_count += 1ULL;

    float fused_alt = fuse_sensor_altitude(lidar_readings, g_fcs.imu_weights.data(), tap_count);
    kalman_predict_and_update(g_fcs.ekf, fused_alt, vertical_accel, dt_sec);

    float pid_thrust = compute_pid_thrust(g_fcs.target_altitude_m, g_fcs.ekf.altitude_m, g_fcs.pid, dt_sec);
    int   safe_ok    = check_collision_envelope(g_fcs.ekf.altitude_m, approach_speed, g_fcs.min_safe_margin_m);

    int mode = select_flight_mode_legacy(g_fcs.ekf.altitude_m, g_fcs.ekf.vertical_vel_mps, safe_ok);
    if (safe_ok == 0) {
        pid_thrust = EMERGENCY_THRUST_MAX;
        cmd.emergency_override = 1;
        g_fcs.envelope_interventions += 1ULL;
    }

    actuate_redundant_servo_bus(pid_thrust, mode);
    g_fcs.last_thrust_pct = pid_thrust;
    g_fcs.current_mode    = mode;

    cmd.fused_altitude_m   = fused_alt;
    cmd.estimated_vel_mps  = g_fcs.ekf.vertical_vel_mps;
    cmd.thrust_pct         = pid_thrust;
    cmd.flight_mode        = mode;
    cmd.safety_envelope_ok = safe_ok;
    return cmd;
}

// -----------------------------------------------------------------------------
// COLD PATH DECLARATIONS (Definitions after main to protect L1i cache)
// -----------------------------------------------------------------------------

[[hft::cold]]
void calibrate_imu_preflight(float target_alt_m, float initial_alt_m);

[[hft::cold]]
void record_flight_telemetry(const ControlCommand& cmd);

[[hft::cold]]
std::string generate_blackbox_summary();

// -----------------------------------------------------------------------------
// Main Entrypoint — 6-Tick Approach & Emergency Braking Differential Test
// -----------------------------------------------------------------------------

int main()
{
    float setpoint = 15.0f;
    float approach_velocity = 8.5f;
    char line[128] = {0};
    if (std::fgets(line, sizeof(line), stdin) != nullptr && line[0] != '\0') {
        char* end1 = nullptr;
        float v1 = std::strtof(line, &end1);
        if (end1 != line) {
            setpoint = v1;
            char* end2 = nullptr;
            float v2 = std::strtof(end1, &end2);
            if (end2 != end1) {
                approach_velocity = v2;
            }
        }
    }

    calibrate_imu_preflight(setpoint, 12.45f);

    float lidar[SENSOR_TAPS] = { 12.4f, 12.5f, 12.3f, 12.6f, 12.4f, 12.5f, 12.5f, 12.4f };
    ControlCommand last_cmd{};

    for (int step = 0; step < 6; ++step) {
        // Simulate subtle descent & sensor variance per 10ms tick
        for (int s = 0; s < SENSOR_TAPS; ++s) {
            lidar[s] -= 0.05f;
        }
        last_cmd = run_1khz_control_tick(lidar, SENSOR_TAPS, -0.25f, approach_velocity, 0.01f);
    }

    record_flight_telemetry(last_cmd);
    return 0;
}

// -----------------------------------------------------------------------------
// COLD PATH IMPLEMENTATIONS — Pre-flight Calibration & Telemetry Logs
// -----------------------------------------------------------------------------

[[hft::cold]]
void calibrate_imu_preflight(float target_alt_m, float initial_alt_m)
{
    g_fcs.ekf.altitude_m       = initial_alt_m;
    g_fcs.ekf.vertical_vel_mps = 0.0f;
    g_fcs.ekf.p_alt            = 0.5f;
    g_fcs.ekf.p_vel            = 0.5f;
    g_fcs.ekf.accel_bias       = 0.02f;

    g_fcs.pid.kp             = 2.2f;
    g_fcs.pid.ki             = 0.35f;
    g_fcs.pid.kd             = 0.45f;
    g_fcs.pid.integral_error = 0.0f;
    g_fcs.pid.prev_error     = 0.0f;
    g_fcs.pid.integral_limit = 25.0f;

    for (int i = 0; i < SENSOR_TAPS; ++i) {
        g_fcs.imu_weights[i] = 0.125f;
    }

    g_fcs.actuator_pwm_bus.store(1000u, std::memory_order_relaxed);
    g_fcs.tick_count             = 0ULL;
    g_fcs.envelope_interventions = 0ULL;
    g_fcs.min_safe_margin_m      = 4.0f;
    g_fcs.target_altitude_m      = target_alt_m;
    g_fcs.last_thrust_pct        = 0.0f;
    g_fcs.current_mode           = MODE_CRUISE;
}

[[hft::cold]]
void record_flight_telemetry(const ControlCommand& cmd)
{
    std::printf(
        "[FlightCtrl] Alt=%.2fm | Vel=%.2fm/s | Thrust=%.2f%% | Mode=%d | SafeEnvelope=%d | Override=%d\n",
        cmd.fused_altitude_m,
        cmd.estimated_vel_mps,
        cmd.thrust_pct,
        cmd.flight_mode,
        cmd.safety_envelope_ok,
        cmd.emergency_override);
}

[[hft::cold]]
std::string generate_blackbox_summary()
{
    std::string summary = "=== Autonomous Flight Controller Blackbox Report ===\n";
    summary += "Control ticks executed  : " + std::to_string(g_fcs.tick_count) + "\n";
    summary += "Safety overrides        : " + std::to_string(g_fcs.envelope_interventions) + "\n";
    summary += "Last thrust command (%) : " + std::to_string(g_fcs.last_thrust_pct) + "\n";
    summary += "Active flight mode      : " + std::to_string(g_fcs.current_mode) + "\n";
    summary += "PWM bus word (hex)      : " + std::to_string(g_fcs.actuator_pwm_bus.load()) + "\n";
    return summary;
}
