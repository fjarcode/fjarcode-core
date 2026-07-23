// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/code_quantum_mldsa_backend_provider.h>
#include <script/code_quantum_mldsa_backend_native.h>
#include <script/code_quantum_mldsa.h>

#include <crypto/sha256.h>

namespace codequantum {

namespace {

MLDSA65NativeBackendBinding g_mldsa65_native_backend_binding{nullptr, nullptr};
MLDSA65NativeBackendTelemetryState g_mldsa65_native_backend_telemetry{
    MLDSA65NativeBackendTelemetryTag::NONE,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
bool g_mldsa65_native_backend_initialized{false};
MLDSA65NativeBackendBinding g_mldsa65_native_backend_implementation_binding_for_testing{nullptr, nullptr};
bool g_mldsa65_native_backend_implementation_binding_for_testing_set{false};

bool MLDSA65NativeBackendBindingSupported(const MLDSA65NativeBackendBinding& binding)
{
    return binding.verify != nullptr || binding.sign != nullptr;
}

MLDSA65BackendAdapterResult NormalizeMLDSA65NativeBackendResult(MLDSA65BackendAdapterResult result)
{
    switch (result) {
    case MLDSA65BackendAdapterResult::VERIFIED:
    case MLDSA65BackendAdapterResult::REJECTED:
    case MLDSA65BackendAdapterResult::UNAVAILABLE:
        return result;
    }
    return MLDSA65BackendAdapterResult::UNAVAILABLE;
}

MLDSA65NativeBackendSignResult NormalizeMLDSA65NativeBackendSignResult(MLDSA65NativeBackendSignResult result)
{
    switch (result) {
    case MLDSA65NativeBackendSignResult::SIGNED:
    case MLDSA65NativeBackendSignResult::REJECTED:
    case MLDSA65NativeBackendSignResult::UNAVAILABLE:
        return result;
    }
    return MLDSA65NativeBackendSignResult::UNAVAILABLE;
}

void SetTelemetryTag(MLDSA65NativeBackendTelemetryTag tag)
{
    g_mldsa65_native_backend_telemetry.last_tag = tag;
}

void RecordRejectWrappedSig()
{
    ++g_mldsa65_native_backend_telemetry.reject_wrapped_sig;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::REJECT_WRAPPED_SIG);
}

void RecordRejectPubKey()
{
    ++g_mldsa65_native_backend_telemetry.reject_pubkey;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::REJECT_PUBKEY);
}

void RecordRejectEmptyScript()
{
    ++g_mldsa65_native_backend_telemetry.reject_empty_script;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::REJECT_EMPTY_SCRIPT);
}

void RecordRejectUnavailable()
{
    ++g_mldsa65_native_backend_telemetry.reject_unavailable;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::REJECT_UNAVAILABLE);
}

void RecordRejectBackend()
{
    ++g_mldsa65_native_backend_telemetry.reject_backend;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::REJECT_BACKEND);
}

void RecordVerified()
{
    ++g_mldsa65_native_backend_telemetry.verified;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::VERIFIED);
}

MLDSA65NativeBackendBinding GetMLDSA65NativeBackendImplementationBindingImpl()
{
    if (g_mldsa65_native_backend_implementation_binding_for_testing_set) {
        return g_mldsa65_native_backend_implementation_binding_for_testing;
    }
    return {nullptr, nullptr};
}

void EnsureMLDSA65NativeBackendBindingInitialized()
{
    if (g_mldsa65_native_backend_initialized) {
        return;
    }
    ++g_mldsa65_native_backend_telemetry.init_attempts;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::INIT_ATTEMPT);
    g_mldsa65_native_backend_initialized = true;

    const MLDSA65NativeBackendBinding implementation_binding = GetMLDSA65NativeBackendImplementationBindingImpl();
    if (MLDSA65NativeBackendBindingSupported(implementation_binding)) {
        g_mldsa65_native_backend_binding = implementation_binding;
        SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::INIT_BOUND_IMPLEMENTATION);
        return;
    }

    const MLDSA65NativeBackendBinding default_binding = GetDefaultMLDSA65NativeBackendBinding();
    if (default_binding.is_available != nullptr || default_binding.verify != nullptr || default_binding.sign != nullptr) {
        if (MLDSA65NativeBackendBindingSupported(default_binding)) {
            g_mldsa65_native_backend_binding = default_binding;
            SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::INIT_BOUND_DEFAULT);
            return;
        }
    }
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::INIT_NO_SUPPORTED_BINDING);
}
#endif

} // namespace

MLDSA65NativeBackendBinding GetMLDSA65NativeBackendImplementationBinding()
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    return GetMLDSA65NativeBackendImplementationBindingImpl();
#else
    return {nullptr, nullptr};
#endif
}

void SetMLDSA65NativeBackendImplementationBindingForTesting(const MLDSA65NativeBackendBinding& binding)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    g_mldsa65_native_backend_implementation_binding_for_testing = binding;
    g_mldsa65_native_backend_implementation_binding_for_testing_set = true;
    g_mldsa65_native_backend_binding = {nullptr, nullptr};
    g_mldsa65_native_backend_initialized = false;
#else
    (void)binding;
#endif
}

void ResetMLDSA65NativeBackendImplementationBindingForTesting()
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    g_mldsa65_native_backend_implementation_binding_for_testing = {nullptr, nullptr};
    g_mldsa65_native_backend_implementation_binding_for_testing_set = false;
    g_mldsa65_native_backend_binding = {nullptr, nullptr};
    g_mldsa65_native_backend_initialized = false;
#endif
}

bool MLDSA65NativeBackendAvailable()
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    EnsureMLDSA65NativeBackendBindingInitialized();
    if (!MLDSA65NativeBackendBindingSupported(g_mldsa65_native_backend_binding)) {
        return false;
    }
    if (g_mldsa65_native_backend_binding.is_available != nullptr) {
        return g_mldsa65_native_backend_binding.is_available();
    }
    return g_mldsa65_native_backend_binding.verify != nullptr;
#else
    return false;
#endif
}

bool MLDSA65NativeBackendSigningAvailable()
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    EnsureMLDSA65NativeBackendBindingInitialized();
    if (!MLDSA65NativeBackendBindingSupported(g_mldsa65_native_backend_binding)) {
        return false;
    }
    if (g_mldsa65_native_backend_binding.sign == nullptr) {
        return false;
    }
    if (g_mldsa65_native_backend_binding.is_available != nullptr) {
        return g_mldsa65_native_backend_binding.is_available();
    }
    return true;
#else
    return false;
#endif
}

std::array<unsigned char, 32> ComputeMLDSA65NativeSigningPrehash(const CScript& scriptCode,
                                                                 unsigned char sighash_type)
{
    std::array<unsigned char, 32> digest{};
    CSHA256 hasher;
    hasher.Write(MLDSA65_NATIVE_SIGN_PREHASH_DOMAIN_TAG.data(), MLDSA65_NATIVE_SIGN_PREHASH_DOMAIN_TAG.size());
    if (!scriptCode.empty()) {
        hasher.Write(scriptCode.data(), scriptCode.size());
    }
    hasher.Write(&sighash_type, 1);
    hasher.Finalize(digest.data());
    return digest;
}

MLDSA65BackendAdapterResult VerifyMLDSA65NativeBackend(const std::vector<unsigned char>& wrapped_sig,
                                                       const std::vector<unsigned char>& vchPubKey,
                                                       const CScript& scriptCode)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    // Enforce structural request validity before any native provider callback.
    // This keeps provider contracts deterministic even for direct calls.
    if (!ParseMLDSA65WrappedSignature(wrapped_sig, nullptr)) {
        RecordRejectWrappedSig();
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    if (!ParseMLDSA65PubKey(vchPubKey, nullptr)) {
        RecordRejectPubKey();
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    if (scriptCode.empty()) {
        RecordRejectEmptyScript();
        return MLDSA65BackendAdapterResult::REJECTED;
    }

    ++g_mldsa65_native_backend_telemetry.verify_invocations;
    SetTelemetryTag(MLDSA65NativeBackendTelemetryTag::VERIFY_INVOCATION);

    EnsureMLDSA65NativeBackendBindingInitialized();
    if (g_mldsa65_native_backend_binding.verify != nullptr && MLDSA65NativeBackendAvailable()) {
        const MLDSA65BackendAdapterResult normalized_result = NormalizeMLDSA65NativeBackendResult(
            g_mldsa65_native_backend_binding.verify(wrapped_sig, vchPubKey, scriptCode));
        if (normalized_result == MLDSA65BackendAdapterResult::VERIFIED) {
            RecordVerified();
            return normalized_result;
        }
        if (normalized_result == MLDSA65BackendAdapterResult::REJECTED) {
            RecordRejectBackend();
            return normalized_result;
        }
        RecordRejectUnavailable();
        return normalized_result;
    }
    RecordRejectUnavailable();
    return MLDSA65BackendAdapterResult::UNAVAILABLE;
#else
    return MLDSA65BackendAdapterResult::UNAVAILABLE;
#endif
}

MLDSA65NativeBackendSignResult SignMLDSA65NativeBackend(const std::vector<unsigned char>& key_material,
                                                        const CScript& scriptCode,
                                                        unsigned char sighash_type,
                                                        std::vector<unsigned char>& out_wrapped_sig)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    out_wrapped_sig.clear();

    if (key_material.empty() || scriptCode.empty() || sighash_type == 0x00) {
        return MLDSA65NativeBackendSignResult::REJECTED;
    }

    EnsureMLDSA65NativeBackendBindingInitialized();
    if (g_mldsa65_native_backend_binding.sign == nullptr) {
        return MLDSA65NativeBackendSignResult::UNAVAILABLE;
    }
    if (g_mldsa65_native_backend_binding.is_available != nullptr &&
        !g_mldsa65_native_backend_binding.is_available()) {
        return MLDSA65NativeBackendSignResult::UNAVAILABLE;
    }

    const std::array<unsigned char, 32> prehashed_sighash32 =
        ComputeMLDSA65NativeSigningPrehash(scriptCode, sighash_type);

    const MLDSA65NativeBackendSignResult normalized_result =
        NormalizeMLDSA65NativeBackendSignResult(
            g_mldsa65_native_backend_binding.sign(key_material, prehashed_sighash32, sighash_type, out_wrapped_sig));
    if (normalized_result != MLDSA65NativeBackendSignResult::SIGNED) {
        out_wrapped_sig.clear();
        return normalized_result;
    }

    MLDSA65WrappedSigView sig_view;
    if (!ParseMLDSA65WrappedSignature(out_wrapped_sig, &sig_view)) {
        out_wrapped_sig.clear();
        return MLDSA65NativeBackendSignResult::REJECTED;
    }
    if (sig_view.sighash_type != sighash_type) {
        out_wrapped_sig.clear();
        return MLDSA65NativeBackendSignResult::REJECTED;
    }
    return MLDSA65NativeBackendSignResult::SIGNED;
#else
    (void)key_material;
    (void)scriptCode;
    (void)sighash_type;
    out_wrapped_sig.clear();
    return MLDSA65NativeBackendSignResult::UNAVAILABLE;
#endif
}

void RegisterMLDSA65NativeBackendBinding(const MLDSA65NativeBackendBinding& binding)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    if (MLDSA65NativeBackendBindingSupported(binding)) {
        g_mldsa65_native_backend_binding = binding;
        g_mldsa65_native_backend_initialized = true;
    } else {
        g_mldsa65_native_backend_binding = {nullptr, nullptr};
        g_mldsa65_native_backend_initialized = false;
    }
#else
    (void)binding;
#endif
}

void ClearMLDSA65NativeBackendBinding()
{
    g_mldsa65_native_backend_binding = {nullptr, nullptr};
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    g_mldsa65_native_backend_initialized = false;
#endif
}

void SetMLDSA65NativeBackendVerifierForTesting(MLDSA65NativeBackendVerifier verifier)
{
    RegisterMLDSA65NativeBackendBinding({nullptr, verifier});
}

void ResetMLDSA65NativeBackendVerifierForTesting()
{
    ClearMLDSA65NativeBackendBinding();
}

void SetMLDSA65NativeBackendSignerForTesting(MLDSA65NativeBackendSigner signer)
{
    RegisterMLDSA65NativeBackendBinding({nullptr, nullptr, signer});
}

void ResetMLDSA65NativeBackendSignerForTesting()
{
    ClearMLDSA65NativeBackendBinding();
}

MLDSA65NativeBackendTelemetryState GetMLDSA65NativeBackendTelemetryState()
{
    return g_mldsa65_native_backend_telemetry;
}

void ResetMLDSA65NativeBackendTelemetryStateForTesting()
{
    g_mldsa65_native_backend_telemetry = {
        MLDSA65NativeBackendTelemetryTag::NONE,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
}

} // namespace codequantum
