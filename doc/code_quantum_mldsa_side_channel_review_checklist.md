# Code Quantum ML-DSA Side-Channel Review Checklist

This checklist is a release-gating security review aid for Code Quantum ML-DSA
verification and signing paths.

## Scope

- `src/script/code_quantum_mldsa.cpp`
- `src/script/code_quantum_mldsa_backend.cpp`
- `src/script/code_quantum_mldsa_backend_provider.cpp`
- `src/script/code_quantum_mldsa_backend_native.cpp`
- Wallet signing integration paths that call ML-DSA provider signing hooks.

## Threat Model Anchors

- Remote adversary can submit malformed envelopes and public keys.
- Local adversary can trigger high-rate signing/verification requests.
- Build/profile drift can accidentally disable hardening assumptions.
- External backend bridges may add timing and memory-observability surfaces.

## Timing Review

- [ ] Verify no secret-dependent early-exit behavior in native signing path.
- [ ] Verify no secret-dependent table lookup in signer/verifier adapters.
- [ ] Verify reject reasons exposed to RPC/UI do not leak private key bits.
- [ ] Measure verify latency distributions for equivalent valid/invalid classes.
- [ ] Measure signing latency distributions across key material classes.

Evidence:
- command:
- artifact path:
- reviewer:

## Branching Review

- [ ] Confirm parser branches are only over public envelope metadata.
- [ ] Confirm mode/algorithm dispatch uses public identifiers only.
- [ ] Confirm backend availability checks do not branch on secret material.
- [ ] Confirm error-code normalization does not branch on secret payload bits.
- [ ] Confirm fallback dispatch order is deterministic and public-data driven.

Evidence:
- command:
- artifact path:
- reviewer:

## Memory Review

- [ ] Confirm temporary signing buffers are cleared on all non-success exits.
- [ ] Confirm output signature buffers are reset before signer invocation.
- [ ] Confirm no out-of-bounds reads on malformed wrapped signatures.
- [ ] Confirm no out-of-bounds reads on malformed public keys.
- [ ] Confirm prehash buffers are fixed-size and stack/heap usage is bounded.
- [ ] Confirm external backend request structs enforce pointer/size consistency.

Evidence:
- command:
- artifact path:
- reviewer:

## Build and Tooling Review

- [ ] Record compiler, optimization profile, and hardening flags used for review.
- [ ] Run ASan/UBSan-enabled unit and functional subset covering ML-DSA paths.
- [ ] Run fuzz corpus for `code_quantum_mldsa` and archive crashes/timeouts.
- [ ] Confirm no new warnings in ML-DSA files under `-Wall -Wextra` profile.

Evidence:
- command:
- artifact path:
- reviewer:

## Operational Abuse and DoS Review Hooks

- [ ] Verify verify-cost bounds remain enforced before expensive dispatch.
- [ ] Verify stack-push and envelope-size limits are enforced pre-dispatch.
- [ ] Verify malformed envelopes reject before cryptographic verification call.
- [ ] Record throughput and worst-case latency under adversarial inputs.

Evidence:
- command:
- artifact path:
- reviewer:

## Sign-Off Template

Review window:
- from:
- to:

Reviewers:
- primary:
- secondary:

Findings summary:
- critical:
- high:
- medium:
- low:

Disposition:
- [ ] Approved for release gate
- [ ] Approved with follow-up issues
- [ ] Blocked pending remediation

Linked issues/PRs:
- 

Notes:
- 
