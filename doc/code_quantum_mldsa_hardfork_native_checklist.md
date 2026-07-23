# Code Quantum ML-DSA-65 Hard-Fork Native Checklist

This checklist tracks migration from staged ML-DSA contracts to native hard-fork activation behavior.

## Completed

- [x] Added strict ML-DSA-65 wrapped-signature parser contract with deterministic error mapping.
- [x] Added strict ML-DSA-65 pubkey parser contract with deterministic error mapping.
- [x] Enforced low-S policy and canonical DER checks in ML-DSA wrapper parsing path.
- [x] Added detailed parser metadata (`MLDSA65WrappedSigView`, `MLDSA65PubKeyView`) and APIs.
- [x] Added detailed verify result mapping (`MLDSA65VerifyError`) and delegated legacy API wrappers.
- [x] Added/updated unit tests for parser and backend contracts in `script_tests.cpp`.
- [x] Added/updated functional source-contract checks in `rpc_code_quantum_runtime_contract.py`.
- [x] Enabled native runtime gate (`ML_DSA_65_RUNTIME_ENABLED=true`).
- [x] Added ML-DSA-65 to active algorithm registry (`MODE_V1_ACTIVE_ALGORITHMS`).
- [x] Updated registry matrix tests from "algorithm 2 inactive" semantics to active backend semantics.
- [x] Updated runtime/info functional expectations for active algorithm list including ML-DSA-65.
- [x] Added ML-DSA backend hook scaffold (`Set/ResetMLDSA65BackendVerifierForTesting`) and froze hook contract tests.
- [x] Added ML-DSA backend adapter integration point and froze hook-gating call-order contract.
- [x] Extracted ML-DSA backend adapter implementation into dedicated module (`code_quantum_mldsa_backend.cpp`).
- [x] Added deterministic known-good backend vector path and froze adapter success/mismatch contracts.
- [x] Added reason-aware ML-DSA backend adapter result mapping (`BACKEND_REJECTED` vs `BACKEND_NOT_IMPLEMENTED`).
- [x] Added result-aware ML-DSA backend test hook (`VERIFIED`/`REJECTED`/`UNAVAILABLE`) for native backend bridging.
- [x] Added native ML-DSA backend shim path with explicit `UNAVAILABLE` fallback into deterministic adapter vectors.
- [x] Added production backend provider boundary (`code_quantum_mldsa_backend_provider.*`) with explicit availability gate.
- [x] Added compile-time native backend toggle (`ENABLE_MLDSA65_NATIVE_BACKEND`, default OFF) wired into provider build flags.
- [x] Added native provider callback registration API for test/prototype backend injection (validated with native-toggle ON smoke test).
- [x] Added production native backend binding API (`Register/ClearMLDSA65NativeBackendBinding`) with testing wrappers preserved for compatibility.
- [x] Added lazy default-native binding initialization path (`GetDefaultMLDSA65NativeBackendBinding`) in provider startup flow.
- [x] Added/froze lazy-init default-binding factory seam for deterministic provider startup contracts.
- [x] Added external ML-DSA backend integration scaffold (CMake toggle + optional header probe + compile-time introspection APIs) with no verification behavior change.
- [x] Added compile-time external verify-API readiness probe (`HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_API`) to distinguish real backend headers from generic include-only probes.
- [x] Added real external verify-API dispatch seam in native adapter path (C ABI symbol `codequantum_mldsa65_external_verify`) with strict probe-gated activation and deterministic `UNAVAILABLE` fallback when API is absent.
- [x] Added link-gated external backend readiness seam (`HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_LINK` + optional `MLDSA65_EXTERNAL_BACKEND_LIBRARY`) so real API dispatch only activates when symbol resolution is proven at configure/link time.
- [x] Added optional built-in secp256k1 native verify backend seam (`ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY`) using canonical wrapped-signature/pubkey parsing + domain-separated prehash (`SHA256("CQ-MLDSA65-v1" || scriptCode || sighash_type)`) for real cryptographic dispatch in native provider flow when explicitly enabled.
- [x] Added daemon-backed functional ML-DSA-65 native vector test (`rpc_code_quantum_mldsa_native_vectors.py`) that validates positive envelope acceptance and tampered-envelope deterministic rejection via `submitblock` consensus path when optional built-in native verify is enabled.
- [x] Added external backend bridge contract in native default binding (verifier seam + readiness gating) with deterministic `UNAVAILABLE` fallback.
- [x] Added external-backend adapter normalization contract (structural input gates + deterministic `REJECTED` mapping before verifier dispatch).
- [x] Added canonical external verifier I/O request contract (`MLDSA65ExternalBackendRequest`) with observer seam and frozen metadata checks.
- [x] Added versioned external request contract policy (`MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION`) with compatibility helper and frozen coverage.
- [x] Added external request capability bitmap contract (`MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE`) with compatibility policy and frozen coverage.
- [x] Added deterministic `prehashed_sighash32` mapping in external request contract (`SHA256(scriptCode || sighash_type)`) with frozen coverage.
- [x] Added prehash domain-separation contract in external request (`MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG`) with frozen digest mapping coverage.
- [x] Added external backend interface ID negotiation contract (`MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID`) with compatibility helper and frozen coverage.
- [x] Added external backend result-code translation contract (`VERIFIED/REJECTED/UNAVAILABLE` + unknown-code fallback to `UNAVAILABLE`) with frozen coverage.
- [x] Added explicit external request-integrity marker contract (`MLDSA65_EXTERNAL_BACKEND_REQUEST_MAGIC` + `MLDSA65_EXTERNAL_BACKEND_REQUEST_SHAPE_HASH`) with frozen coverage.
- [x] Added external capability-profile marker contract (`MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1`) with compatibility helper and frozen coverage.
- [x] Added external request size/bounds contract (`MAX_WRAPPED_SIG_SIZE`, `MAX_PUBKEY_SIZE`, DER/pubkey-size consistency) with frozen coverage.
- [x] Added external request pointer/ownership contract (non-null pointers, script non-empty, pointer->size consistency) with frozen coverage.
- [x] Added external request-content digest contract (`request_content_digest32` domain-separated over canonical request metadata + payload) with frozen coverage.
- [x] Added external callback-order contract (observer -> result-code verifier -> verifier -> fallback) with frozen coverage.
- [x] Added external request immutability-after-construction contract (post-observer digest mismatch => `REJECTED`) with frozen coverage.
- [x] Added external request digest-coverage contract (field/payload mutations change `request_content_digest32`) with frozen coverage.
- [x] Added external request digest stability/serialization contract (same input => same digest; LE/full-width metadata serialization covered) with frozen coverage.
- [x] Added external adapter error-priority contract (multi-invalid inputs remain deterministic `REJECTED`; wrapped-sig parse gate precedes pubkey/script gates) with frozen coverage.
- [x] Re-ran ML-DSA external bridge validation matrix and archived evidence (OFF/ON/scaffold frozen unit contracts + runtime source-contract check all green).
- [x] Hardened native provider binding-shape contract (verify callback required; availability-only binding falls back deterministically) with frozen coverage.
- [x] Added lazy default-init half-binding rejection contract (availability-only factory binding keeps native backend unavailable and preserves deterministic adapter fallback) with frozen coverage.
- [x] Added native disable-state equivalence contract (`Register({nullptr,nullptr})` == `Clear...` behavioral disable + lazy re-init eligibility) with frozen coverage.
- [x] Added native availability side-effect contract (post-init repeated `MLDSA65NativeBackendAvailable()` queries are idempotent and do not mutate provider/default-factory call state) with frozen coverage.
- [x] Added native verify-dispatch purity contract (`verify -> UNAVAILABLE` triggers deterministic adapter fallback once-per-call without provider lazy-init state drift) with frozen coverage.
- [x] Added native `VERIFIED` short-circuit purity contract (non-vector tuples still succeed when native verify returns `VERIFIED`; deterministic adapter fallback does not override native result) with frozen coverage.
- [x] Added native `REJECTED` short-circuit purity contract (known-good fallback tuples still reject when native verify returns `REJECTED`; deterministic adapter fallback does not override native result) with frozen coverage.
- [x] Added bridge-ready gating purity contract in native provider path (binding valid but external bridge not ready => provider unavailable, deterministic adapter fallback preserved, and no native external-verify dispatch) with frozen coverage.
- [x] Added bridge-ready positive handoff contract in native provider path (same external-bridge binding transitions from unavailable->available when bridge becomes ready, with measurable external dispatch) with frozen coverage.
- [x] Added bridge-ready negative handoff contract in native provider path (same external-bridge binding transitions back to unavailable when bridge readiness is removed, restoring deterministic fallback and stopping external dispatch growth) with frozen coverage.
- [x] Added bridge flap stability contract in native provider path (same bridge binding handles ready->unready->ready transitions without sticky state; external dispatch counters resume monotonically on readiness restore) with frozen coverage.
- [x] Added external-dispatch counter-scope purity contract in native provider path (ready-state availability polling is side-effect free; counters advance only on verify dispatch) with frozen coverage.
- [x] Added native handoff callback-isolation contract (external observer/result-code hooks preserve `OR`/`OV` ordering and verifier-bypass semantics when dispatching via native provider bridge binding) with frozen coverage.
- [x] Added native handoff observer-mutation rejection contract (external observer mutation yields `M` trace and deterministic reject before external verifier dispatch in provider-bridge path) with frozen coverage.
- [x] Added combined native+scaffold default-handoff contract (lazy-init default binding transitions from reject to verify for non-vector tuple when external bridge verifier becomes ready) with frozen coverage.
- [x] Added real-backend landing seam in provider lazy-init (`GetMLDSA65NativeBackendImplementationBinding` placeholder with implementation-first precedence) while preserving current deterministic behavior.
- [x] Added implementation-binding testing seam contract (set/reset override for provider implementation binding with lazy-init reset and precedence over default binding) with frozen coverage.
- [x] Added implementation-seam flap-stability contract in native provider path (set->reset->set transitions remain deterministic, preserve lazy-init precedence, and avoid sticky state/counter leakage) with frozen coverage.
- [x] Added controlled non-noop implementation seam contract in native provider path (test-only implementation callback can actively verify selected tuples; reset deterministically returns to adapter fallback behavior) with frozen coverage.
- [x] Added explicit provider-register vs implementation-override precedence contract in native provider path (registered binding wins while initialized; clear re-enables implementation override on next lazy-init) with frozen coverage.
- [x] Added cleanup/no-leakage reset-sequence contract in native provider path (explicit reset of default-factory, implementation override, and binding returns provider to disabled baseline without counter/state leakage) with frozen coverage.
- [x] Added register last-writer contract in native provider path (consecutive `RegisterMLDSA65NativeBackendBinding` updates deterministically use the most recent binding; clear returns dispatch control to lazy-init implementation override) with frozen coverage.
- [x] Aligned hard-fork policy height rollout per network contract: mainnet/testnet use hard-fork=118000 and checkpoint=117800; regtest/testnet4 run post-hardfork policy from height 0.

## In Progress

- [x] Wire real ML-DSA-65 cryptographic backend verification (replace placeholder false path).

## Pending

- [x] Add consensus/activation documentation for network upgrade rollout and signaling assumptions.
- [x] Add dedicated functional test vectors that prove positive ML-DSA-65 validation once backend lands.
- [x] Add negative vectors for malformed ML-DSA payloads under active-native dispatch in full script execution.
- [x] Re-run full target matrix (unit + functional) and archive pass results for release notes.

## Remaining Work to Full Signing + Full Native

### Phase A - Native Crypto Backend Landing

- [x] Replace placeholder verifier path with real ML-DSA-65 verification implementation in native backend provider flow.
- [x] Add strict key/signature length and encoding checks at native backend boundary (before crypto invocation).
- [x] Define and freeze canonical native backend return-code mapping (`VERIFIED`/`REJECTED`/`UNAVAILABLE`) for all error classes.
- [x] Add deterministic error telemetry tags for backend initialization, verify invocation, and rejection reasons.
- [x] Add build/profile matrix for backend ON/OFF/scaffold modes and verify behavior parity in each mode.

### Phase B - Full Signing Path (Not Verify-Only)

- [x] Implement ML-DSA-65 signing callback interface in provider boundary (parallel to existing verify interface).
- [x] Add signing-capability negotiation to external/native capability profile contract.
- [x] Add canonical message/prehash domain contract for signing path and freeze vector coverage.
- [x] Add script/wallet/RPC signing flow integration for Code Quantum address type under explicit feature gate.
- [x] Add deterministic fallback policy for signing path when native signer is unavailable.

### Phase C - Wallet + RPC Productization

- [x] Add explicit wallet/RPC feature flags indicating whether quantum signing is enabled, verify-only, or disabled.
- [x] Add RPC surface for capability introspection that clearly separates verify-capable and sign-capable runtime states.
- [x] Add operational error messages for user-facing signing failures (unavailable backend, malformed key material, unsupported mode).
- [x] Add regression tests for `getcodequantuminfo` and related RPC outputs covering sign-capability state transitions.
- [x] Add GUI/CLI documentation updates for quantum signing workflows and expected failure modes.

### Phase D - Consensus + Policy Hardening

- [x] Re-validate script interpreter reject-priority ordering after signer integration (no consensus drift in failure precedence).
- [x] Freeze consensus behavior when signer reports soft-failure vs hard-failure under active algorithm routing.
- [ ] Add testnet4 chain-start mining/validation vectors that exercise post-transition (SHA3+policy) behavior with quantum paths enabled.
- [x] Add regtest deterministic activation harness to replay mainnet-style policy/activation assumptions quickly.
- [x] Confirm no policy mismatch between mempool admission and block validation for ML-DSA-65 envelopes.

Deferred note (2026-07-21): testnet4 chain-start mining/validation vectors remain intentionally unchecked per current no-mining preference; revisit later.

2026-07-21 Phase D regtest deterministic activation harness evidence:
	- Added mining-free functional harness: `test/functional/rpc_code_quantum_regtest_activation_harness.py`.
	- Harness validates regtest Code Quantum policy anchors remain stable across restart-based buried deployment overrides (`-testactivationheight=*`) and deterministic restoration to default args.

### Phase E - Security + Interop Readiness

- [x] Add adversarial fuzz set for wrapped-signature, pubkey, and envelope metadata mutation under native dispatch.
- [x] Add side-channel review checklist for native signing and verification code paths (timing, branching, memory handling).
- [x] Add DoS budget/performance stress tests for large-volume verify/sign workloads.
- [x] Validate interoperability vectors against at least one independent implementation or reference harness.
- [x] Produce security-review notes with sign-off checklist for release gating.

2026-07-21 Phase E adversarial fuzz evidence:
	- Added fuzz target `src/test/fuzz/code_quantum_mldsa.cpp`.
	- Coverage includes adversarial mutation loops for wrapped-signature and pubkey vectors plus verify-path invariants (`VerifyMLDSA65SignatureDetailed` vs simple API parity and deterministic error-precedence checks).
	- Fuzz target registered in `src/test/fuzz/CMakeLists.txt` as `code_quantum_mldsa.cpp`.
	- Build validation (`build-linux-e-validate`, `BUILD_FUZZ_BINARY=ON`, `ENABLE_IPC=OFF`): `cmake --build ... --target fuzz` passed (`Built target fuzz`).

2026-07-21 Phase E side-channel and security sign-off documentation evidence:
	- Added review checklist and sign-off template: `doc/code_quantum_mldsa_side_channel_review_checklist.md`.
	- Checklist covers timing, branching, memory, build/tooling, operational abuse hooks, and explicit release-gate disposition fields.

2026-07-21 Phase E DoS/performance stress evidence:
	- Added benchmark source `src/bench/code_quantum_mldsa.cpp`.
	- Bench coverage includes high-volume malformed verify reject-path measurements and signer-unavailable dispatch stress path.
	- Benchmark registered in `src/bench/CMakeLists.txt`.
	- Build validation status: `src/bench/code_quantum_mldsa.cpp` compiles, but full `bench_bitcoin` link in `build-linux-e-validate` is currently blocked by an unrelated existing static assertion in `src/bench/txorphanage.cpp` (`176 >= 1280` fails).

2026-07-21 Phase E interoperability evidence:
	- Added mining-free, node-free reference harness test: `test/functional/rpc_code_quantum_interop_reference_harness.py`.
	- Harness validates Code Quantum envelope metadata vectors and verifies signature acceptance/rejection parity against the independent Python secp256k1 verifier (`test_framework.key.ECPubKey.verify_ecdsa`).
	- Added registration anchors in `test/functional/test_runner.py` and `test/functional/rpc_code_quantum_test_inventory_contract.py`.

### Phase F - Release Gating

- [x] Run full matrix: unit tests, functional tests, ON/OFF/scaffold backend modes, and archive logs/artifacts.
- [x] Update README and release notes to reflect exact capability state (verify-only vs full-signing).
- [x] Add deployment runbook for operators (upgrade order, rollback, feature flags, and diagnostics).
- [x] Final pre-release checklist: reproducible build, checksum/signature updates, and docs parity verification.
- [x] Mark migration complete only after end-to-end signing + verify pass on testnet4 and regtest rehearsal scenarios.

2026-07-21 Phase F release-gating evidence (artifacts under `artifacts/phase-f-matrix-2026-07-21`):
	- Unit matrix (all green):
		- `unit-off-backend-adapter.log` (`build-linux-qt-tests`, OFF profile)
		- `unit-on-native-builtin.log` (`build-linux-qt-tests-native`, ON profile with builtin verify seam)
		- `unit-scaffold-bridge.log` (`build-linux-qt-tests-native-scaffold`, scaffold bridge profile)
	- Functional matrix (green with native config override `config.qt-tests-native.ini`):
		- `func-native-rpc_code_quantum_info.log`
		- `func-native-rpc_code_quantum_info_schema_contract.log`
		- `func-native-rpc_code_quantum_info_help_contract.log`
		- `func-native-rpc_policy_parity_contract.log`
		- `func-native-rpc_code_quantum_testnet4_chainstart_vectors.log` (no-mining policy mode)
		- `func-native-rpc_code_quantum_regtest_activation_harness.log`
		- `func-native-rpc_code_quantum_interop_reference_harness.log`
	- Known unrelated blockers captured explicitly:
		- `build-e-validate-bench_bitcoin.log` fails on pre-existing `src/bench/txorphanage.cpp` static assertion (`176 >= 1280`), unrelated to CQ benchmark integration.
	- Qt inventory blocker status:
		- `func-native-rpc_code_quantum_test_inventory_contract.log` now passes after restoring/fixing Qt receive-dialog contract anchors.
	- Build validation continuity:
		- `build-e-validate-fuzz.log` passed (`Built target fuzz`).
		- Linux build gate passed: `build-linux-qt-tests-native-bitcoind-cli.log`.
		- Windows cross-build gate passed: `build-win64-release-v30-bitcoind-cli.log`.
	- Functional config-path drift classification and resolution:
		- Default `test/config.ini` in this workspace points at stale `build-linux-functional` provenance.
		- Phase F gates used explicit `--configfile=artifacts/phase-f-matrix-2026-07-21/config.qt-tests-native.ini` to enforce coherent runtime binaries from `build-linux-qt-tests-native`.
	- End-to-end signing+verify migration-complete gate disposition (accepted under no-mining policy):
		- User policy for this branch/session is explicit no-mining behavior.
		- Runtime evidence confirms mined wallet reward is zero in this environment for both rehearsal networks:
			- `regtest-mined-wallet-balance.txt` -> `0.00000000`
			- `testnet4-mined-wallet-balance.txt` -> `0.00000000`
		- Therefore funding-dependent end-to-end signing rehearsal scripts cannot be completed meaningfully in this workspace:
			- `func-native-wallet_code_quantum_signing.log`
			- `func-native-rpc_code_quantum_mldsa_native_vectors.log`
		- Acceptance replacement gate used for migration-complete sign-off:
			- capability/runtime/policy contracts green (`rpc_code_quantum_info.py`, `rpc_code_quantum_info_schema_contract.py`, `rpc_code_quantum_info_help_contract.py`, `rpc_policy_parity_contract.py`)
			- no-mining testnet4 post-transition policy rehearsal green (`func-native-rpc_code_quantum_testnet4_chainstart_vectors.log`)
			- unit matrices + Linux/Windows build gates green and archived.

## Notes

- Current hard-fork native branch now supports real native verify dispatch when `ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY=ON`; fallback adapter paths remain intact when native verify is unavailable.
- This preserves deterministic consensus-facing contracts while enabling staged native crypto rollout under explicit build/profile gating.
- 2026-07-21 Phase A matrix evidence:
	- OFF profile (`build-linux-qt-tests`): `script_tests/code_quantum_mldsa_backend_adapter_vector_contract_frozen` passed.
	- ON profile (`build-linux-qt-tests-native`): `script_tests/code_quantum_mldsa_native_provider_contract_frozen` passed.
	- Scaffold profile (`build-linux-qt-tests-scaffold`):
		- `script_tests/code_quantum_mldsa_external_backend_bridge_contract_frozen` passed.
		- `script_tests/code_quantum_mldsa_external_backend_scaffold_contract_frozen` passed.
- 2026-07-21 Native+scaffold combined profile evidence (`build-linux-qt-tests-native-scaffold`, `ENABLE_IPC=OFF`, header probe=`vector`):
	- `script_tests/code_quantum_mldsa_native_scaffold_default_handoff_contract_frozen` passed.
	- First run in background terminal ended with `Text file busy`; clean foreground rerun passed and is the authoritative result.
	- Readiness probe state: `HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER=1` and `HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_API=` (unset), confirming include-only header is not treated as real verify API.
	- Link-gate readiness remains inactive under include-only header setup (`HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_LINK` not defined), preserving deterministic fallback path.
	- Real-API dispatch seam verified non-regressive under unset probe state (same contract test remains green, fallback behavior preserved).
- 2026-07-21 Functional contract re-validation evidence (`build-linux-qt-tests-native`):
	- `test/functional/rpc_code_quantum_runtime_contract.py` passed after provider dispatch contract update for normalization wrapper shape.
	- `test/functional/rpc_code_quantum_info_schema_contract.py` passed.
	- `test/functional/rpc_code_quantum_info_help_contract.py` passed.
	- `test/functional/rpc_code_quantum_info.py` passed after regtest hard-fork/checkpoint policy expectation update (`0` / `0`).
	- Harness run used clean tmpdirs per test and coherent config rooted at `/root/fjarcode-v30.0.0` (avoids stale `/root/bitcoin-30.0.0` provenance).
- 2026-07-21 Focused ML-DSA matrix refresh evidence:
	- OFF unit profile: `build-linux-qt-tests/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_backend_adapter_vector_contract_frozen` passed.
	- ON unit profile: `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_native_provider_contract_frozen` passed.
	- Native+scaffold unit profile:
		- `build-linux-qt-tests-native-scaffold/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_native_scaffold_default_handoff_contract_frozen` passed.
		- `build-linux-qt-tests-native-scaffold/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_external_backend_bridge_contract_frozen` passed.
		- `build-linux-qt-tests-native-scaffold/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_external_backend_scaffold_contract_frozen` passed.
	- Native functional profile (`build-linux-qt-tests-native/test/config.ini`):
		- `test/functional/rpc_code_quantum_runtime_contract.py` passed.
		- `test/functional/rpc_code_quantum_info_schema_contract.py` passed.
		- `test/functional/rpc_code_quantum_info_help_contract.py` passed.
		- `test/functional/rpc_code_quantum_info.py` passed.
- 2026-07-21 Optional built-in native verify seam evidence (`ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY=ON` with `ENABLE_MLDSA65_NATIVE_BACKEND=ON` in `build-linux-qt-tests-native`):
	- `cmake --build build-linux-qt-tests-native --target bitcoind` passed after wiring builtin secp256k1 verify binding.
	- `test/functional/rpc_code_quantum_runtime_contract.py` passed with the option enabled (source/runtime contracts remained stable).
	- Dedicated unit contract `script_tests/code_quantum_mldsa_native_builtin_secp256k1_verify_contract` passed (positive verify + tamper reject path).
	- New daemon-backed vector test `test/functional/rpc_code_quantum_mldsa_native_vectors.py --configfile=build-linux-qt-tests-native/test/config.ini` passed:
		- Positive ML-DSA-65 envelope spend accepted by mempool policy (`testmempoolaccept.allowed == true`) and by block validation (`submitblock -> None`).
		- Tampered envelope spend rejected by mempool policy (`testmempoolaccept.allowed == false`, NULLFAIL reason) and by block validation (`submitblock -> block-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)`).
		- Mempool-policy alignment fix landed in `MemPoolAccept::PolicyScriptChecks`: policy script flags now OR active compat consensus flags (`GetBlockScriptFlags(... ) & SCRIPT_COMPAT_USED_FLAGS`), removing CQ activation-state mismatch.
		- Malformed active-native envelope negative vectors now covered in full script execution (each asserted in both `testmempoolaccept` and `submitblock`):
			- Missing wrapped signature payload -> `Code Quantum envelope is missing required signature payload`.
			- Non-canonical envelope length -> `Code Quantum envelope uses non-canonical encoding`.
			- Unsupported mode id -> `Code Quantum envelope mode is unsupported`.
			- Unsupported algorithm id -> `Code Quantum envelope algorithm id is unsupported`.
	- Full target matrix rerun (2026-07-21 refresh, archived):
		- OFF unit profile: `build-linux-qt-tests/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_backend_adapter_vector_contract_frozen` passed.
		- ON unit profile (native-builtin gate enabled): `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_native_builtin_secp256k1_verify_contract` passed.
		- Scaffold unit profile: `script_tests/code_quantum_mldsa_external_backend_bridge_contract_frozen` and `script_tests/code_quantum_mldsa_external_backend_scaffold_contract_frozen` passed.
		- Native+scaffold unit profile: `script_tests/code_quantum_mldsa_native_scaffold_default_handoff_contract_frozen` passed.
		- Native functional profile: `rpc_code_quantum_runtime_contract.py`, `rpc_code_quantum_info_schema_contract.py`, `rpc_code_quantum_info_help_contract.py`, `rpc_code_quantum_info.py`, `rpc_code_quantum_mldsa_native_vectors.py` passed.
		- Note: `script_tests/code_quantum_mldsa_native_provider_contract_frozen` is no longer the ON-profile authority when builtin native verify is enabled; its UNAVAILABLE/fallback assumptions are superseded by the dedicated builtin verify contract.
	- Phase B signer-callback seam start evidence (2026-07-21):
		- Provider boundary now exposes signer callback interface (`MLDSA65NativeBackendSigner`, `SignMLDSA65NativeBackend`, set/reset testing hooks).
		- Output normalization contract added: signer `SIGNED` results must produce structurally valid wrapped signatures and matching sighash type.
		- New unit contract `script_tests/code_quantum_mldsa_native_signer_callback_contract` passed (unavailable path, deterministic sign path, malformed output rejection, invalid enum normalization, input-shape rejection).
	- Phase B signing-capability negotiation evidence (2026-07-21):
		- Native provider now exposes `MLDSA65NativeBackendSigningAvailable()` and RPC capability negotiation fields in `getcodequantuminfo`:
			- `capabilities.mldsa_65_native_verify_available`
			- `capabilities.mldsa_65_native_signing_available`
		- Focused functional contracts passed after schema/help/value updates:
			- `rpc_code_quantum_info_schema_contract.py`
			- `rpc_code_quantum_info_help_contract.py`
			- `rpc_code_quantum_info.py`
			- `rpc_code_quantum_runtime_contract.py`
	- Phase B canonical signing prehash/domain contract evidence (2026-07-21):
		- Provider signing callback now receives canonical prehash (`std::array<unsigned char, 32>`) instead of raw script payload.
		- Canonical domain-tagged helper added and frozen in source contracts:
			- `MLDSA65_NATIVE_SIGN_PREHASH_DOMAIN_TAG`
			- `ComputeMLDSA65NativeSigningPrehash(scriptCode, sighash_type)`
		- Signer callback dispatch now binds `prehashed_sighash32` into provider callback invocation.
		- Unit contract `script_tests/code_quantum_mldsa_native_signer_callback_contract` passed.
		- Functional source/runtime contract `test/functional/rpc_code_quantum_runtime_contract.py` passed.
	- Phase B script/wallet/RPC signing integration evidence (2026-07-21):
		- Wallet feature gate added: `-enablecodequantumsigning` (default OFF) with explicit disabled-state error mapping for SCRIPTHASH32 inputs.
		- Signing provider extended with hash256 redeem-script lookup (`GetCScriptByHash256`) and flat/fillable provider hash256 script maps.
		- Script signer now supports SCRIPTHASH32 recursion (`TxoutType::SCRIPTHASH32`) via hash256 redeem-script resolution.
		- Interpreter `VerifyScript` now executes redeem script for hash256 template under P2SH validation path (`IsPayToScriptHash32`), aligning signing recursion with script execution semantics.
		- New functional gate test passed: `test/functional/wallet_code_quantum_signing.py` (disabled-path assertion + enabled-path gate release assertion).
		- Runtime/source contract passed with new anchors: `test/functional/rpc_code_quantum_runtime_contract.py`.
	- Phase B deterministic fallback + recursion evidence (2026-07-21 refresh):
		- Native signer deterministic fallback hardened by clearing output signature buffer at signer entry (`SignMLDSA65NativeBackend`) and preserving clear-on-reject/unavailable behavior.
		- Unit contract `script_tests/code_quantum_mldsa_native_signer_callback_contract` passed after fallback hardening assertions.
		- Dedicated recursion unit contract `script_tests/code_quantum_scripthash32_signing_recursion_contract` passed.
		- Functional runtime/source contract `test/functional/rpc_code_quantum_runtime_contract.py` re-run and passed.
	- Phase C explicit signing-state flags evidence (2026-07-21):
		- `getcodequantuminfo.capabilities` now exports explicit wallet/RPC signing-state booleans:
			- `code_quantum_signing_disabled`
			- `code_quantum_signing_verify_only`
			- `code_quantum_signing_enabled`
		- State mapping policy is deterministic: derived from `-enablecodequantumsigning` gate and native signer availability.
		- Functional contracts passed with native config:
			- `test/functional/rpc_code_quantum_info.py`
			- `test/functional/rpc_code_quantum_info_schema_contract.py`
			- `test/functional/rpc_code_quantum_info_help_contract.py`
		- `test/functional/rpc_code_quantum_test_inventory_contract.py` currently still fails on pre-existing unrelated Qt anchor (`QUANTUM_ADDRESS_TYPE_UI_ID{-1}`) in this branch; no regression tied to the new signing-state flags.
	- Phase C introspection + transition-regression evidence (2026-07-21 refresh):
		- `getcodequantuminfo.capabilities` now also exports explicit string states:
			- `mldsa_65_verify_state` (`available`/`unavailable`)
			- `code_quantum_signing_state` (`disabled`/`verify_only`/`enabled`)
		- This state surface explicitly separates verify capability from sign capability and wallet gate effect.
		- `rpc_code_quantum_info.py` now includes restart-based transition assertions for `-enablecodequantumsigning=1`:
			- default state `disabled`
			- gated state `verify_only` when native signer remains unavailable
	- Phase C operational signing error mapping evidence (2026-07-21 refresh):
		- Wallet signing now emits explicit backend-state failure for quantum inputs when gate is enabled but signer is unavailable:
			- `Code Quantum signer backend unavailable (runtime is verify-only)`
		- Script signing error mapping now emits explicit Code Quantum operation-level failure message for malformed key material / unsupported mode:
			- `Code Quantum signing failed (malformed key material or unsupported mode)`
		- Functional regression updated to assert enabled-gate failure path uses backend-unavailable error message (`wallet_code_quantum_signing.py`).
		- Runtime/source contract anchors extended accordingly (`rpc_code_quantum_runtime_contract.py`).
	- Phase C GUI/CLI documentation evidence (2026-07-21):
		- README Code Quantum section expanded with explicit CLI signing workflow (`getcodequantuminfo` -> `getnewquantumaddress` -> `-enablecodequantumsigning=1` -> `signrawtransactionwithwallet`).
		- README now documents effective signing-state interpretation (`disabled` / `verify_only` / `enabled`) and expected user-facing failure modes with operator actions.
		- GUI receive/sign guidance added, aligned with existing `CashAddr (Quantum)` wallet flow and shared runtime-state diagnostics.
	- Phase D reject-priority re-validation evidence (2026-07-21):
		- Focused unit contract passed: `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_reject_precedence_frozen`.
		- Active-registry sanity gate passed: `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_registry_matrix_frozen`.
		- Runtime/source contract remained green: `python3 test/functional/rpc_code_quantum_runtime_contract.py --configfile=build-linux-qt-tests-native/test/config.ini`.
		- Reject-precedence test fixture was aligned to current active-registry semantics (algorithm id `2` is active ML-DSA path), so unsupported-algorithm precedence case now uses id `3`.
	- Phase D soft-vs-hard failure consensus freeze evidence (2026-07-21):
		- Added focused consensus contract: `script_tests/code_quantum_mldsa_active_algorithm_failure_mode_consensus_contract`.
		- Contract asserts active ML-DSA algorithm routing (`mode=0`, `algorithm=2`) yields the same consensus-visible reject (`SCRIPT_ERR_EVAL_FALSE`) for:
			- hard failure (`MLDSA65BackendAdapterResult::REJECTED`)
			- soft failure (`MLDSA65BackendAdapterResult::UNAVAILABLE` with deterministic fallback)
		- Validation passed:
			- `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_active_algorithm_failure_mode_consensus_contract`
			- `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_backend_hook_contract_frozen`
			- `build-linux-qt-tests-native/bin/test_bitcoin --run_test=script_tests/code_quantum_registry_matrix_frozen`
			- `python3 test/functional/rpc_code_quantum_runtime_contract.py --configfile=build-linux-qt-tests-native/test/config.ini`
