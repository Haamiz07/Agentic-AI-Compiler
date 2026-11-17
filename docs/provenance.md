# Build provenance report

Each completed pipeline run writes a JSON build receipt next to its final LLVM
IR file. The receipt ends in `.provenance.json` and records SHA-256 fingerprints
for the source file, final IR, and generated binary (when one is available).
It also records the frontend IR origin (`clang` or `stub`), discovered tool
versions, target configuration, security findings, and optimization decisions
with their validation summaries.

## Run and verify

From the project root, compile one of the bundled examples:

```sh
python3 src/pipeline.py examples/crypto_constant_time_vault.cpp --binary
```

The run prints the report path. It is normally under `/tmp/agentic_c/ir/`.
Verify the recorded files with:

```sh
python3 src/pipeline.py --verify-provenance /tmp/agentic_c/ir/crypto_constant_time_vault.ll.provenance.json
```

The verifier exits with status `0` when every recorded artifact is present and
matches its fingerprint. It exits with status `1` for an unreadable manifest,
a missing artifact, or a hash mismatch. Editing or deleting an artifact after
the build is a simple way to demonstrate a failed verification.

## Scope and limitations

This is a hash-based integrity check against the manifest. It detects changes
to recorded files after the receipt was written, but the receipt is not signed;
it does not establish who created it or prevent someone from replacing both an
artifact and its manifest. Matching hashes also do not prove that a program is
secure or correct. The report labels stub IR explicitly so a fallback run is
not presented as a real Clang frontend build.
