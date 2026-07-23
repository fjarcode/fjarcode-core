# Code Quantum ML-DSA-65 Hard-Fork Activation Runbook

This runbook defines the operational path for native ML-DSA-65 activation in the hard-fork branch.

## Scope

- Consensus dispatch for Code Quantum algorithm id 2 is active.
- Runtime capability flag reports ML-DSA-65 as enabled.
- Current backend verifier remains placeholder and intentionally returns false on verify path.

## Current Consensus Behavior

- Envelope and algorithm routing:
  - mode 0 + algorithm 0: wrapped ECDSA DER path.
  - mode 0 + algorithm 1: SHA3-256t wrapped ECDSA path.
  - mode 0 + algorithm 2: ML-DSA-65 native dispatch path.
- Reject precedence:
  - non-canonical envelope rejects before backend dispatch.
  - unknown algorithm id rejects as unsupported algorithm.
  - known algorithm id 2 with structurally valid envelope currently reaches backend and evaluates false.

## Activation Invariants

- IDs are fixed and must not drift:
  - MODE_V1_WRAPPED_ECDSA = 0
  - ALGORITHM_V1_WRAPPED_ECDSA_DER = 0
  - ALGORITHM_V1_SHA3_256T = 1
  - ALGORITHM_V1_ML_DSA_65 = 2
- Registry sets:
  - Known algorithms include 0, 1, 2.
  - Active algorithms include 0, 1, 2.
- Runtime capability:
  - ML_DSA_65_RUNTIME_ENABLED = true

## Backend Integration Checklist (Next Engineering Step)

- Define exact ML-DSA-65 signature/public-key wire format for script-level payloads.
- Implement deterministic backend verification function for algorithm 2.
- Preserve existing parse reason contracts and expand with backend failure classes only if required.
- Add positive and negative vectors for script execution (consensus path, not only parser path).
- Ensure legacy algorithms 0 and 1 remain behaviorally unchanged.

## Test Gate Commands

Run these before merging any ML-DSA backend changes:

```bash
cmake --build build-linux-qt-tests -j4 --target test_bitcoin
./build-linux-qt-tests/bin/test_bitcoin --run_test=script_tests/code_quantum_registry_matrix_frozen*
./build-linux-qt-tests/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_parser_contract_frozen*
./build-linux-qt-tests/bin/test_bitcoin --run_test=script_tests/code_quantum_mldsa_backend_contract_frozen*
python3 test/functional/rpc_code_quantum_runtime_contract.py
```

Optional contract checks (environment-dependent in this workspace at the moment):

```bash
python3 test/functional/rpc_code_quantum_info.py
python3 test/functional/rpc_code_quantum_info_schema_contract.py
python3 test/functional/rpc_code_quantum_info_help_contract.py
```

## Rollout Notes

- This branch intentionally separates "consensus dispatch activation" from "cryptographic backend completion".
- The separation reduces merge risk by freezing parser/dispatch behavior first.
- Final release gating must include successful positive ML-DSA-65 validation vectors.

## Operator Deployment Runbook

### Upgrade order

1. Upgrade passive/observer nodes first and confirm baseline health.
2. Upgrade non-critical wallet/RPC nodes next with default signing gate state (disabled).
3. Upgrade critical wallet/RPC nodes last; keep signing gate disabled until diagnostics are green.
4. Enable signing gate only on explicitly selected signer nodes after capability validation.

### Mandatory pre-enable checks

Run these checks before enabling wallet signing on any node:

```bash
fjarcode-cli getcodequantuminfo
```

Required interpretation:
- `capabilities.mldsa_65_verify_state` must be `available` for active verify runtime.
- `capabilities.code_quantum_signing_state` should be:
  - `disabled` before opt-in,
  - `verify_only` if gate is enabled but signer backend is unavailable,
  - `enabled` only when signer backend is available.

### Feature flags and runtime policy

- `-enablecodequantumsigning=0` (default): verify-capable runtime, wallet signing disabled.
- `-enablecodequantumsigning=1`: wallet signing enabled only if signer backend is available; otherwise runtime reports `verify_only`.
- Do not force-enable signing fleet-wide in one step. Roll out by node cohort with health checks between cohorts.

### Diagnostics and failure mapping

Expected user-facing failure classes:
- `Code Quantum input signing is disabled (-enablecodequantumsigning=1 to enable)`
  - Action: enable signing gate on intended signer node and restart.
- `Code Quantum signer backend unavailable (runtime is verify-only)`
  - Action: keep node in verify-only mode or move signing to a signing-capable profile/backend.
- `Code Quantum signing failed (malformed key material or unsupported mode)`
  - Action: validate key/material shape, address/script coherence, and mode assumptions.

Suggested quick triage sequence:
1. `getcodequantuminfo` and confirm `capabilities` state fields.
2. Verify node args and deployment profile match expected signer/non-signer role.
3. Re-run targeted signing test on a non-critical node before changing production signer nodes.

### Rollback policy

Rollback triggers:
- Unexpected divergence between `getcodequantuminfo` state and observed signing behavior.
- Regressions in CQ functional contracts or policy parity gates.
- Any consensus/policy mismatch between mempool admission and block validation for CQ envelopes.

Rollback actions:
1. Immediately disable wallet signing gate on affected nodes (`-enablecodequantumsigning=0`) and restart.
2. Keep nodes in verify-capable mode while isolating signer path regression.
3. Revert only the latest CQ deployment step (smallest-scoped rollback).
4. Re-run the last known-good gate set before re-attempting rollout.

### Release-gate dependency

- Do not mark migration complete until end-to-end signing plus verify scenarios pass in rehearsal flows (regtest and testnet4 policy scenario).
