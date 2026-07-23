// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_PROVIDER_H
#define BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_PROVIDER_H

#include <script/code_quantum_mldsa_backend.h>

#include <array>
#include <cstdint>

namespace codequantum {

using MLDSA65NativeBackendVerifier = MLDSA65BackendAdapterResult (*)(const std::vector<unsigned char>& wrapped_sig,
                                                                     const std::vector<unsigned char>& vchPubKey,
                                                                     const CScript& scriptCode);
using MLDSA65NativeBackendAvailability = bool (*)();
constexpr std::array<unsigned char, 18> MLDSA65_NATIVE_SIGN_PREHASH_DOMAIN_TAG{
    'C', 'Q', '-', 'M', 'L', 'D', 'S', 'A', '6', '5', '-', 'S', 'I', 'G', 'N', '-', 'v', '1'};
enum class MLDSA65NativeBackendSignResult : uint8_t {
    SIGNED = 0,
    REJECTED,
    UNAVAILABLE,
};
using MLDSA65NativeBackendSigner = MLDSA65NativeBackendSignResult (*)(const std::vector<unsigned char>& key_material,
                                                                      const std::array<unsigned char, 32>& prehashed_sighash32,
                                                                      unsigned char sighash_type,
                                                                      std::vector<unsigned char>& out_wrapped_sig);

struct MLDSA65NativeBackendBinding {
    MLDSA65NativeBackendAvailability is_available;
    MLDSA65NativeBackendVerifier verify;
    MLDSA65NativeBackendSigner sign{nullptr};
};

enum class MLDSA65NativeBackendTelemetryTag : uint8_t {
    NONE = 0,
    INIT_ATTEMPT,
    INIT_BOUND_IMPLEMENTATION,
    INIT_BOUND_DEFAULT,
    INIT_NO_SUPPORTED_BINDING,
    VERIFY_INVOCATION,
    REJECT_WRAPPED_SIG,
    REJECT_PUBKEY,
    REJECT_EMPTY_SCRIPT,
    REJECT_UNAVAILABLE,
    REJECT_BACKEND,
    VERIFIED,
};

struct MLDSA65NativeBackendTelemetryState {
    MLDSA65NativeBackendTelemetryTag last_tag;
    uint64_t init_attempts;
    uint64_t verify_invocations;
    uint64_t reject_wrapped_sig;
    uint64_t reject_pubkey;
    uint64_t reject_empty_script;
    uint64_t reject_unavailable;
    uint64_t reject_backend;
    uint64_t verified;
};

// Production backend provider boundary for ML-DSA verification.
// The default implementation reports unavailable until a native crypto backend
// is linked and enabled in this build.
bool MLDSA65NativeBackendAvailable();
bool MLDSA65NativeBackendSigningAvailable();
std::array<unsigned char, 32> ComputeMLDSA65NativeSigningPrehash(const CScript& scriptCode,
                                                                 unsigned char sighash_type);
MLDSA65BackendAdapterResult VerifyMLDSA65NativeBackend(const std::vector<unsigned char>& wrapped_sig,
                                                       const std::vector<unsigned char>& vchPubKey,
                                                       const CScript& scriptCode);
MLDSA65NativeBackendSignResult SignMLDSA65NativeBackend(const std::vector<unsigned char>& key_material,
                                                        const CScript& scriptCode,
                                                        unsigned char sighash_type,
                                                        std::vector<unsigned char>& out_wrapped_sig);

// Real-backend landing seam: implementation binding can be wired independently
// of default/test bindings. Current contract keeps this UNAVAILABLE.
MLDSA65NativeBackendBinding GetMLDSA65NativeBackendImplementationBinding();
void SetMLDSA65NativeBackendImplementationBindingForTesting(const MLDSA65NativeBackendBinding& binding);
void ResetMLDSA65NativeBackendImplementationBindingForTesting();

void RegisterMLDSA65NativeBackendBinding(const MLDSA65NativeBackendBinding& binding);
void ClearMLDSA65NativeBackendBinding();

void SetMLDSA65NativeBackendVerifierForTesting(MLDSA65NativeBackendVerifier verifier);
void ResetMLDSA65NativeBackendVerifierForTesting();
void SetMLDSA65NativeBackendSignerForTesting(MLDSA65NativeBackendSigner signer);
void ResetMLDSA65NativeBackendSignerForTesting();

MLDSA65NativeBackendTelemetryState GetMLDSA65NativeBackendTelemetryState();
void ResetMLDSA65NativeBackendTelemetryStateForTesting();

} // namespace codequantum

#endif // BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_PROVIDER_H
