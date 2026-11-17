# Architecture & Engineering Decision Records (ADR)
## Secure Agentic AI Compiler Optimization System

This document records the architectural, design, safety, and implementation decisions made during the development and end-to-end integration of the Secure Agentic AI Compiler.

---

### ADR-001: Real Toolchain Integration (Clang++ and LLVM `opt`) vs. Simulated Stubs

* **Context:** The inherited codebase relied primarily on hard-coded stub IR strings and simulated latency reductions. To produce verifiable compilation artifacts, the system needed to interface with real LLVM tooling on both POSIX and Windows platforms.
* **Decision:**
  * Implement toolchain auto-discovery in `src/core/frontend.py`, `src/safety/runner.py`, and `src/safety/validator.py` searching standard directories (e.g. `C:\msys64\clang64\bin`, `C:\Program Files\LLVM\bin`, `/usr/local/bin`).
  * Default to `clang++` for C++ source files to properly link runtime symbols and C++ standard library libraries (`libc++`/`libstdc++`).
  * Emit LLVM IR at `-O0` using `-Xclang -disable-O0-optnone -gline-tables-only` so the generated `.ll` retains source line traceability (`!dbg` / `!DILocation`) while remaining mutable by subsequent `opt` passes.
  * Retain syntactically valid IR stubs strictly as an emergency fallback if no Clang binary exists on the host.
* **Status:** Accepted and implemented.

---

### ADR-002: Fail-Closed Optimization Policy Gate

* **Context:** LLM agents and autonomous tuners can hallucinate non-existent passes, execute arbitrary shell commands, or apply unsafe transformations that break semantics or security guarantees.
* **Decision:**
  * Enforce an immutable, fail-closed allowlist of 17 vetted LLVM middle-end passes in `src/safety/policy.py`.
  * Validate pass names against a strict regex (`^[a-zA-Z0-9_\-]+$`) before subprocess execution. Any flag injection (`;`, `|`, `&`, `$`, `-mllvm`) is rejected immediately without invoking a shell.
  * Every pass execution in `src/safety/runner.py` is two-phase: apply transformation (`opt -passes=<pass> -S`), then independently verify (`opt -passes=verify -disable-output`).
* **Status:** Accepted and implemented.

---

### ADR-003: Live Entrance Prompt-Injection Filtering (Stage 0 Guard)

* **Context:** Attackers can embed adversarial prompt directives (direct prompt overrides, instructions to ignore policy gates, or data exfiltration trojans) inside source code comments or string literals.
* **Decision:**
  * Rather than restricting attack detection to an offline testbed, elevate `SecurityAnalyzer.scan_adversarial_directives()` to an active compiler entrance gate (Stage 0) in `src/pipeline.py`.
  * If prompt-injection phrases (e.g., `SYSTEM PROMPT OVERRIDE`, `ignore security instructions`, `mark unsafe as safe`) are detected, compilation halts optimization fail-closed.
  * Optimization attempts record an `<entrance-prompt-guard>` rejection event, keeping the baseline unoptimized IR intact.
* **Status:** Accepted and implemented.

---

### ADR-004: Closed-Loop Critic Feedback and Fallback Pass Injection

* **Context:** The initial prototype operated in an open-loop batch mode: agents proposed a sequence of passes, and the policy gate accepted or rejected them without informing the planner or attempting self-correction.
* **Decision:**
  * Implement an inner iterative loop in `SafeOptimizationController.step_action()` and `optimize()`:
    $$\text{Planner proposes pass} \longrightarrow \text{Policy Gate checks} \longrightarrow \text{LLVM Runner applies} \longrightarrow \text{Validator tests} \longrightarrow \text{Critic Feedback to Planner}$$
  * When a pass is rejected (e.g., non-allowlisted `always-inline`) or fails validation, the controller queries `_FALLBACK_ALTERNATIVES` and injects allowlisted substitutes (e.g. `inline`, `simplifycfg`) into the active optimization queue marked as `critic_fallback(<pass>)`.
* **Status:** Accepted and implemented.

---

### ADR-005: Security-Informed Agent Reasoning

* **Context:** Static security findings (CWE-120 buffer overflow risks, unsafe `strcpy`/`gets` calls, pointer arithmetic) were previously detected but ignored by the downstream optimization agents.
* **Decision:**
  * Introduce `SecurityAnalyzer.summarize_for_planner()` to partition findings into:
    * `prefer_passes`: Transformations that eliminate vulnerabilities (e.g., `sroa`, `mem2reg` to eliminate stack buffers and promote variables to SSA registers).
    * `avoid_passes`: Transformations that could worsen memory safety around vulnerable locations (e.g., `loop-unroll`, `loop-vectorize`).
  * Ingest these findings into `CompilationContext`, `BossAgent._apply_security_overlay()`, `IRTunerAgent.build_priority_queue()`, and `HWTunerAgent.build_priority_queue()`.
* **Status:** Accepted and implemented.

---

### ADR-006: Candidate Validation and Empirical Microbenchmarking

* **Context:** Relying solely on cost-model heuristics does not prove that optimized binaries execute correctly or deliver real-world wall-clock latency reductions.
* **Decision:**
  * Implement `CandidateValidator` in `src/safety/validator.py` to compile baseline and candidate IR into native executables via `clang++`.
  * Test execution equivalence against multiple representative stdin behavior fixtures (`""`, `"100\n"`, `"1000 250 5\n"`), requiring identical return codes, stdout, and stderr.
  * Run empirical microbenchmarking with warm-up cycles and multi-run median wall-clock nanosecond timing (`_benchmark_runs()`), reporting speedup percentages in both CLI and Web UI.
  * Optimize compilation performance: Cache the baseline binary across pass steps in `_get_compiled_baseline()` to reduce validation overhead from 35s+ down to ~3-4s.
* **Status:** Accepted and implemented.

---

### ADR-007: Experience Store Embedding Compatibility

* **Context:** `IR2VecEncoder` produced 64-dimensional IR structural embeddings, whereas the production PostgreSQL/pgvector schema was defined with 256 dimensions, causing NumPy shape alignment exceptions during vector similarity comparisons.
* **Decision:**
  * Update `SQLiteStore._cosine()` in `src/memory/experience_store.py` to dynamically align vectors using wrap-padding: `np.pad(v, (0, target_len - len(v)), mode="wrap")`.
  * Ensure backward and forward compatibility between 64-d heuristic encoders and 256-d neural embedding models.
* **Status:** Accepted and implemented.

---

### ADR-008: Zero-Dependency Interactive Web Dashboard

* **Context:** The system required a user-facing visualization and demonstration interface without introducing heavyweight external dependencies or complex deployment setups.
* **Decision:**
  * Build the Web UI server in `src/web_ui/app.py` using Python's standard library `http.server`.
  * Expose REST endpoints:
    * `GET /api/results`: Serves pipeline execution metrics, timing breakdown, and stage progression.
    * `GET /api/source`: Supplies source code for example benchmarks.
    * `POST /api/compile`: Allows interactive browser editing of C/C++ source and triggers live compilation.
    * `GET /api/attack-lab`: Returns real-time security scenario evaluation metrics (Precision, Recall, F1).
* **Status:** Accepted and implemented.

