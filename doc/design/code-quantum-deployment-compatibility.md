# Code Quantum Deployment Compatibility, Migration, and Rollback Rules

This document defines deployment-time rules for the Code Quantum (CQ) surface in the BTC30 migration tree.
It is scoped to currently active behavior and contract tests in this repository.

## Scope

Covered runtime surfaces:
- Script/interpreter CQ envelope dispatch and error mapping.
- Shared CQ constants and algorithm registry in `src/script/code_quantum_params.h`.
- Node RPC reporting via `getcodequantuminfo`.
- Address and wallet CQ RPCs (`getcodequantumaddress`, `getnewquantumaddress`, and `getnewaddress` default/selector behavior).

Out of scope:
- Introducing new CQ algorithm IDs beyond the current active set.
- Changing consensus activation heights or chain policy anchors without a dedicated migration gate.

## Compatibility Rules

1. CQ constant source of truth
- CQ envelope and registry constants must be defined in `src/script/code_quantum_params.h`.
- `src/script/interpreter.cpp` and `src/rpc/node.cpp` must consume those constants, not duplicate divergent values.

2. CQ registry and dispatch compatibility
- Supported mode set must include wrapped mode `0`.
- Known algorithms for mode `0` are currently:
  - `0`: wrapped ECDSA DER path.
  - `1`: SHA3-256t path.
-  - `2`: ML-DSA-65 path.
- Active algorithms for mode `0` are currently:
  - `0`: wrapped ECDSA DER path.
  - `1`: SHA3-256t path.
  - `2`: ML-DSA-65 path.
- Unknown mode or algorithm IDs must remain deterministic reject paths with stable script errors.

3. CQ envelope budget compatibility
- Envelope budget limits are part of the public runtime contract:
  - max wrapped signature size: `73`.
  - max envelope size: `79`.
- Budget changes are consensus/policy-impacting and require dedicated tests and rollout notes before deployment.

4. Script flag compatibility safety
- Custom migration flags in `src/script/script_flags.h` must never overlap upstream `SCRIPT_VERIFY_*` range.
- `IsExplicitCompatFlagsContext(flags)` must guard custom semantics so complemented/unsanitized test flags do not accidentally activate CQ/FJAR behavior.

5. RPC compatibility contract
- `getcodequantuminfo` must keep stable top-level sections for runtime/policy reporting, including `active_algorithms` and `policy`.
- `policy.activation_matrix` and `policy.genesis` fields are contract surfaces; changes require help/schema contract updates.
- `getcodequantumaddress` must keep strict 32-byte hash input validation and emit CQ metadata fields (`isquantum`, `quantum_type`, `quantum_hash`).

6. Wallet/RPC compatibility contract
- `getnewquantumaddress` must continue returning a CQ cashaddr destination and setting wallet address-book purpose to receive.
- `getnewaddress` with omitted `address_type` and explicit `address_type="quantum"` must continue using CQ generation path unless an explicit migration gate changes default policy.

## Migration Rules

1. Additive-first rollout
- New CQ capabilities (new mode, algorithm, or policy behavior) must be introduced additively first (known/disabled), then activated in a later explicit gate.

2. Single-gate change discipline
- For each CQ behavior change, include all of:
  - interpreter/runtime change,
  - RPC/reporting update (if user-visible),
  - unit and functional contract updates,
  - checklist gate evidence in `doc/design/fjarcode-migration-checklist-30.0.0.md`.

3. Contract test requirements
- At minimum, run relevant CQ unit and functional tests before marking a migration step complete.
- Recommended minimum command set:
  - `./build-linux-qt-tests/bin/test_bitcoin --run_test=script_tests`
  - `build-linux-functional/test/functional/test_runner.py --jobs=1 --combinedlogslen=200 rpc_code_quantum_info.py rpc_code_quantum_address.py rpc_getnewquantumaddress.py`

4. Build-mode isolation
- Do not toggle fuzzing mode in an active unit-test build directory.
- Use a dedicated fuzz build directory for CQ fuzz execution evidence.

## Rollback Rules

1. Fast rollback trigger
- Roll back the current CQ deployment step if any of the following fails after a change:
  - CQ unit contracts,
  - CQ functional RPC/help/schema contracts,
  - script/miner/tx focused regression sweep used by the active migration gate.

2. Rollback granularity
- Revert only the latest CQ step (smallest possible scope).
- Keep prior validated CQ gates intact and avoid cross-phase reverts.

3. Post-rollback verification
- After rollback, rerun the exact gate command set from the previously green checkpoint and re-record results in the checklist notes.

4. Divergence handling
- If runtime behavior and RPC reporting drift, prioritize restoring shared constant wiring and contract tests before re-attempting feature rollout.

## Operational Notes

- Test runner warnings about unrelated background `bitcoind` processes indicate potential contention risk; rerun if observed results are inconsistent.
- This deployment rule set should be updated only together with a dated migration-checklist gate note and fresh test evidence.
