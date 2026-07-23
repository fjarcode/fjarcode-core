# Code Quantum ML-DSA-65 Pre-Release Checklist

This checklist is the final release gate companion for CQ/ML-DSA work.

## Scope

- Verify that release artifacts, reproducibility evidence, and CQ documentation are aligned.
- Track known unrelated blockers separately so CQ migration status remains accurate.

## 1. Reproducible Build Gate

- [ ] Build from clean tree using release profile.
- [ ] Reproduce deterministic binaries with at least one independent builder.
- [ ] Verify matching hashes for expected release artifacts.
- [ ] Record build environment metadata (toolchain, CMake version, profile flags).

## 2. Checksum and Signature Gate

- [ ] Generate checksum manifest for all deliverables.
- [ ] Generate detached signatures for checksum manifest.
- [ ] Verify signatures against trusted release keys.
- [ ] Archive checksum/signature files with release candidate tag notes.

## 3. CQ Runtime and Capability Gate

- [ ] Confirm `getcodequantuminfo` schema/help/value contracts pass in release-profile runtime.
- [ ] Confirm explicit capability states are documented and match runtime behavior:
  - `mldsa_65_verify_state`
  - `code_quantum_signing_state`
- [ ] Confirm default wallet posture is signing disabled unless explicitly opted in.

## 4. CQ Matrix and Regression Gate

- [ ] Unit matrix pass recorded for OFF/ON/scaffold profiles.
- [ ] Functional matrix pass recorded for parity/info/interop/regtest harness tests.
- [ ] Fuzz target build pass recorded (`fuzz`).
- [ ] Bench status recorded; if blocked, blocker is classified as unrelated or release-critical.
- [ ] Known unrelated blockers are listed with evidence logs and owner follow-up issue.

## 5. Documentation Parity Gate

- [ ] `README.md` reflects current verify/signing capability state.
- [ ] `doc/release-notes.md` includes CQ capability-state release note.
- [ ] `doc/code_quantum_mldsa_hardfork_activation_runbook.md` includes operator rollout, rollback, flags, and diagnostics.
- [ ] `doc/code_quantum_mldsa_hardfork_native_checklist.md` Phase F evidence is current.

## 6. Final Go/No-Go Conditions

- [ ] End-to-end signing plus verify scenarios pass for regtest rehearsal.
- [ ] End-to-end signing plus verify scenarios pass for testnet4 rehearsal policy path.
- [ ] No unresolved release-critical regressions remain in CQ consensus/policy behavior.
- [ ] Release manager sign-off captured with date and commit hash.

## Known Blocker Tracking (Current Branch)

- Qt inventory contract anchor gap (`QUANTUM_ADDRESS_TYPE_UI_ID{-1}`) is currently tracked as unrelated to CQ signing/verify migration behavior.
- `bench_bitcoin` build may be blocked by existing `src/bench/txorphanage.cpp` static assertion in some validation profiles.

## Evidence Links

Record dated artifact directories here, for example:
- `artifacts/phase-f-matrix-YYYY-MM-DD/`
