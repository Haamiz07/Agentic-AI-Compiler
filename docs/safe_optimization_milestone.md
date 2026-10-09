# Safe optimization milestone

## What changed

The existing Boss and tuning agents still propose work as before. A new safety layer now sits between those recommendations and LLVM:

1. `SecurityAnalyzer` scans the source and generated LLVM IR for a small set of risky calls and memory-copy patterns. Findings include rule, severity, file, line, function (when recognizable), and a short snippet.
2. `PassPolicy` normalizes each suggested action and checks it against the configured pass allowlist. Unknown actions, malformed values, duplicate passes, and recommendations over the per-run limit are skipped with a reason.
3. `LLVMOptRunner` invokes `opt` as a subprocess without a shell and checks its output with LLVM's IR verifier.
4. `CandidateValidator` compiles both the original and candidate IR using clang. In strict mode it also runs both binaries on configured stdin fixtures and compares exit status, stdout, and stderr. A failed check rejects the candidate and the last accepted IR remains selected.
5. The pipeline emits the binary from the selected IR, includes findings and per-pass decisions in its result/dashboard JSON, and saves memory entries only when at least one real pass was accepted by validation.

## Policy and failure behavior

The allowlist is in `configs/config.yaml` under `policy_gate`. It contains the pass names this prototype permits. The policy does not accept shell text or arbitrary compiler flags. If `opt` is missing, a pass fails, IR verification fails, clang cannot compile, or a required behavior fixture differs, that candidate is rejected and the original or last accepted IR is retained.

The default sets `validation.require_behavior_checks: true`. The bundled examples do not read stdin, so the configuration includes an empty-input (EOF) smoke fixture. This allows the validator to compare their baseline and candidate executions. It is only a narrow smoke check, not representative coverage for arbitrary programs. Replace or add trusted inputs under `validation.behavior_inputs` when compiling programs that read stdin. Example:

```yaml
validation:
  require_behavior_checks: true
  behavior_inputs:
    - "valid example input\n"
    - "boundary case input\n"
```

These are stdin strings. The baseline and candidate are run with the same inputs and compared exactly. Set `require_behavior_checks: false` only when compile-only acceptance is appropriate for a demonstration; compile success alone does not establish equivalent behavior.

## Scope and limitations

This is a conservative starter scanner, not a complete security analyzer or proof of program correctness. It uses transparent pattern rules, can miss issues or raise false alarms, and source function/line association is approximate. LLVM IR findings point to IR lines; exact source mapping requires debug-location metadata and is future work. Fixture checks cover only the supplied inputs and do not prove correctness on every input. Running fixture binaries with timeouts and a temporary working directory is not a full operating-system sandbox; use only trusted project inputs and fixtures.

The current tuner agents can still be in stub/demo mode and their latency/reward numbers are not real benchmark measurements. This milestone governs actual pass execution and candidate acceptance; it does not turn the planner into an autonomous LLM or establish production-grade security/performance claims.

## How it fits the intended architecture

`C/C++ source → clang IR → security analysis → existing planner/tuners → policy gate → opt pass runner → IR verifier + clang/fixture validation → selected IR → existing output, report, and memory`

The new layer adds the control and evidence boundary needed before adding a richer planner, critic, or learned memory policy. See `src/safety/` for the separate models and components.
