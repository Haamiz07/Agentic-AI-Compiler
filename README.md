# Secure Agentic AI Compiler

An academic C/C++ compiler optimization prototype. It emits LLVM IR, scans the
source and IR for selected risky patterns, lets agents propose optimization
passes, checks those passes against an allowlist, runs LLVM's `opt` verifier,
and validates candidate behavior against configured input fixtures.

## Quick start

Requirements: Python 3, `clang`/`clang++`, and LLVM `opt`. The compiler tools
must be on `PATH` or discoverable by the project's toolchain lookup. Install
the Python dependencies in a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install numpy pyyaml
```

On macOS, install the Xcode Command Line Tools (`xcode-select --install`). The
compiler locates the active macOS SDK with `xcrun` and passes it to Clang.

Run a bundled C++ example from the repository root:

```sh
python src/pipeline.py examples/crypto_constant_time_vault.cpp --binary
```

The pipeline prints its output paths and writes a provenance report next to
the final LLVM IR, normally under `/tmp/agentic_c/ir/`. The report has the
suffix `.provenance.json`.

## Verify build artifacts

Pass the report path printed by the compile run:

```sh
python src/pipeline.py --verify-provenance /tmp/agentic_c/ir/crypto_constant_time_vault.ll.provenance.json
```

Verification exits with status `0` if all listed artifact files exist and
their SHA-256 hashes match the report. It exits with status `1` if an artifact
is missing or changed. See [docs/provenance.md](docs/provenance.md) for the
report fields, demo steps, and limits.

## Main components

- `src/pipeline.py`: coordinates the compilation and optimization run.
- `src/safety/analysis.py`: pattern-based source and IR security scanning.
- `src/safety/policy.py` and `src/safety/runner.py`: pass allowlisting and
  guarded LLVM pass execution.
- `src/safety/validator.py`: compile, fixture comparison, and optional timing
  and footprint measurements.
- `src/safety/provenance.py`: artifact fingerprinting and report verification.
- `src/web_ui/`: local pipeline dashboard and Attack Lab interface.
- `examples/`: C/C++ demonstration inputs.

## Important limits

This is a prototype, not a security certification tool. The scanner uses
heuristics and may miss issues or report false positives. Fixture checks cover
only configured inputs. Timing figures are prototype measurements, and the
agent tuners can use stub/demo behavior. A provenance report detects changes
relative to its recorded hashes, but it is not signed and does not prove who
created it. A matching report does not prove that the program is secure or
correct. Stub IR fallback is labeled in the report as `ir_origin: "stub"`.
