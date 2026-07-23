// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/code_quantum_mldsa_backend_native.h>
#include <script/code_quantum_mldsa.h>

#include <crypto/sha256.h>
#include <pubkey.h>
#include <uint256.h>

namespace codequantum {

namespace {

MLDSA65NativeBackendBindingFactory g_mldsa65_native_default_binding_factory{nullptr};
MLDSA65NativeBackendVerifier g_mldsa65_external_backend_verifier{nullptr};
MLDSA65ExternalBackendRequestObserver g_mldsa65_external_backend_request_observer{nullptr};
MLDSA65ExternalBackendResultCodeVerifier g_mldsa65_external_backend_result_code_verifier{nullptr};

#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_API) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_LINK)
extern "C" int codequantum_mldsa65_external_verify(const unsigned char* der_sig,
                                                     size_t der_sig_len,
                                                     const unsigned char* pubkey_payload,
                                                     size_t pubkey_payload_len,
                                                     const unsigned char* prehashed_sighash32,
                                                     size_t prehashed_sighash32_len);
#endif

void WriteUint32LE(CSHA256& hasher, uint32_t value)
{
    const unsigned char bytes[4]{
        static_cast<unsigned char>(value & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff),
        static_cast<unsigned char>((value >> 16) & 0xff),
        static_cast<unsigned char>((value >> 24) & 0xff),
    };
    hasher.Write(bytes, sizeof(bytes));
}

void WriteUint64LE(CSHA256& hasher, uint64_t value)
{
    const unsigned char bytes[8]{
        static_cast<unsigned char>(value & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff),
        static_cast<unsigned char>((value >> 16) & 0xff),
        static_cast<unsigned char>((value >> 24) & 0xff),
        static_cast<unsigned char>((value >> 32) & 0xff),
        static_cast<unsigned char>((value >> 40) & 0xff),
        static_cast<unsigned char>((value >> 48) & 0xff),
        static_cast<unsigned char>((value >> 56) & 0xff),
    };
    hasher.Write(bytes, sizeof(bytes));
}

std::array<unsigned char, 32> ComputeExternalBackendPrehashedSighash(const CScript& scriptCode,
                                                                      unsigned char sighash_type)
{
    std::array<unsigned char, 32> digest{};
    CSHA256 hasher;
    hasher.Write(MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG.data(), MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG.size());
    if (!scriptCode.empty()) {
        hasher.Write(scriptCode.data(), scriptCode.size());
    }
    hasher.Write(&sighash_type, 1);
    hasher.Finalize(digest.data());
    return digest;
}

bool ExternalBackendAvailable()
{
    return MLDSA65ExternalBackendBridgeReady();
}

MLDSA65BackendAdapterResult ExternalBackendVerify(const std::vector<unsigned char>& wrapped_sig,
                                                  const std::vector<unsigned char>& vchPubKey,
                                                  const CScript& scriptCode)
{
    return VerifyMLDSA65ExternalBackendAdapter(wrapped_sig, vchPubKey, scriptCode);
}

MLDSA65BackendAdapterResult VerifyMLDSA65ExternalBackendViaApi(const MLDSA65ExternalBackendRequest& request)
{
#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_API) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_LINK)
    if (!MLDSA65ExternalBackendRequestPointersSupported(request)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    const unsigned char* der_sig = request.wrapped_sig->data() + request.der_sig_offset;
    const unsigned char* pubkey_payload = request.pubkey->data() + request.pubkey_payload_offset;
    const int verify_code = codequantum_mldsa65_external_verify(
        der_sig,
        request.der_sig_size,
        pubkey_payload,
        request.pubkey_payload_size,
        request.prehashed_sighash32.data(),
        request.prehashed_sighash32.size());
    if (verify_code > 0) {
        return MLDSA65BackendAdapterResult::VERIFIED;
    }
    if (verify_code == 0) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    return MLDSA65BackendAdapterResult::UNAVAILABLE;
#else
    (void)request;
    return MLDSA65BackendAdapterResult::UNAVAILABLE;
#endif
}

#if defined(ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY)
bool BuiltinSecp256k1BackendAvailable()
{
    return true;
}

MLDSA65BackendAdapterResult VerifyMLDSA65BuiltinSecp256k1Backend(const std::vector<unsigned char>& wrapped_sig,
                                                                 const std::vector<unsigned char>& vchPubKey,
                                                                 const CScript& scriptCode)
{
    MLDSA65WrappedSigView wrapped_sig_view;
    if (!ParseMLDSA65WrappedSignature(wrapped_sig, &wrapped_sig_view)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    MLDSA65PubKeyView pubkey_view;
    if (!ParseMLDSA65PubKey(vchPubKey, &pubkey_view)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    if (scriptCode.empty()) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    if (wrapped_sig_view.der_sig_offset + wrapped_sig_view.der_sig_size > wrapped_sig.size()) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }

    std::vector<unsigned char> der_sig(
        wrapped_sig.begin() + wrapped_sig_view.der_sig_offset,
        wrapped_sig.begin() + wrapped_sig_view.der_sig_offset + wrapped_sig_view.der_sig_size);
    CPubKey pubkey(vchPubKey.begin(), vchPubKey.end());
    if (!pubkey.IsFullyValid()) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }

    const std::array<unsigned char, 32> prehashed_sighash =
        ComputeExternalBackendPrehashedSighash(scriptCode, wrapped_sig_view.sighash_type);
    const uint256 digest(std::span<const unsigned char>(prehashed_sighash.data(), prehashed_sighash.size()));
    if (pubkey.Verify(digest, der_sig)) {
        return MLDSA65BackendAdapterResult::VERIFIED;
    }
    return MLDSA65BackendAdapterResult::REJECTED;
}
#endif

} // namespace

MLDSA65NativeBackendBinding GetDefaultMLDSA65NativeBackendBinding()
{
    if (g_mldsa65_native_default_binding_factory != nullptr) {
        return g_mldsa65_native_default_binding_factory();
    }

#if defined(ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY)
    return {BuiltinSecp256k1BackendAvailable, VerifyMLDSA65BuiltinSecp256k1Backend};
#endif

    if (MLDSA65ExternalBackendScaffoldEnabled() && MLDSA65ExternalBackendHeaderDetected()) {
        return {ExternalBackendAvailable, ExternalBackendVerify};
    }

    return {nullptr, nullptr};
}

bool MLDSA65ExternalBackendScaffoldEnabled()
{
#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD)
    return true;
#else
    return false;
#endif
}

bool MLDSA65ExternalBackendHeaderDetected()
{
#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
    return true;
#else
    return false;
#endif
}

bool MLDSA65ExternalBackendBridgeReady()
{
    if (!MLDSA65ExternalBackendScaffoldEnabled()) {
        return false;
    }
    if (!MLDSA65ExternalBackendHeaderDetected()) {
        return false;
    }
#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_API) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_LINK)
    return true;
#else
    return g_mldsa65_external_backend_verifier != nullptr;
#endif
}

bool MLDSA65ExternalBackendRequestVersionSupported(uint32_t request_version)
{
    return request_version == MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION;
}

bool MLDSA65ExternalBackendCapabilitiesSupported(uint32_t capability_flags)
{
    if ((capability_flags & MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE) != MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE) {
        return false;
    }
    const uint32_t unknown_flags = capability_flags & ~MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE;
    return unknown_flags == 0;
}

bool MLDSA65ExternalBackendCapabilityProfileSupported(uint32_t capability_profile_id)
{
    return capability_profile_id == MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1;
}

bool MLDSA65ExternalBackendInterfaceIdSupported(const std::array<unsigned char, 16>& interface_id)
{
    return interface_id == MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID;
}

bool MLDSA65ExternalBackendResultCodeSupported(uint8_t result_code)
{
    return result_code == MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_VERIFIED ||
           result_code == MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED ||
           result_code == MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_UNAVAILABLE;
}

bool MLDSA65ExternalBackendRequestSizesSupported(size_t wrapped_sig_size,
                                                 size_t pubkey_size,
                                                 size_t der_sig_size,
                                                 size_t pubkey_payload_size)
{
    if (wrapped_sig_size == 0 || wrapped_sig_size > MLDSA65_EXTERNAL_BACKEND_MAX_WRAPPED_SIG_SIZE) {
        return false;
    }
    if (pubkey_size == 0 || pubkey_size > MLDSA65_EXTERNAL_BACKEND_MAX_PUBKEY_SIZE) {
        return false;
    }
    if (der_sig_size == 0 || der_sig_size + 1 != wrapped_sig_size) {
        return false;
    }
    if (pubkey_payload_size + 1 != pubkey_size) {
        return false;
    }
    return true;
}

bool MLDSA65ExternalBackendRequestPointersSupported(const MLDSA65ExternalBackendRequest& request)
{
    if (request.wrapped_sig == nullptr || request.pubkey == nullptr || request.script_code == nullptr) {
        return false;
    }
    if (request.script_code->empty()) {
        return false;
    }
    return MLDSA65ExternalBackendRequestSizesSupported(
        request.wrapped_sig->size(),
        request.pubkey->size(),
        request.der_sig_size,
        request.pubkey_payload_size);
}

std::array<unsigned char, 32> ComputeMLDSA65ExternalBackendRequestContentDigest(const MLDSA65ExternalBackendRequest& request)
{
    std::array<unsigned char, 32> digest{};
    if (request.wrapped_sig == nullptr || request.pubkey == nullptr || request.script_code == nullptr) {
        return digest;
    }

    CSHA256 hasher;
    hasher.Write(MLDSA65_EXTERNAL_BACKEND_REQUEST_DIGEST_DOMAIN_TAG.data(), MLDSA65_EXTERNAL_BACKEND_REQUEST_DIGEST_DOMAIN_TAG.size());
    WriteUint32LE(hasher, request.request_version);
    WriteUint32LE(hasher, request.capability_flags);
    WriteUint32LE(hasher, request.capability_profile_id);
    hasher.Write(request.request_magic.data(), request.request_magic.size());
    WriteUint32LE(hasher, request.request_shape_hash);
    hasher.Write(request.external_backend_interface_id.data(), request.external_backend_interface_id.size());
    WriteUint64LE(hasher, request.der_sig_offset);
    WriteUint64LE(hasher, request.der_sig_size);
    WriteUint64LE(hasher, request.pubkey_payload_offset);
    WriteUint64LE(hasher, request.pubkey_payload_size);
    hasher.Write(&request.sighash_type, 1);
    const unsigned char compressed_flag = request.pubkey_is_compressed ? 1 : 0;
    hasher.Write(&compressed_flag, 1);
    hasher.Write(request.prehash_domain_tag.data(), request.prehash_domain_tag.size());
    hasher.Write(request.prehashed_sighash32.data(), request.prehashed_sighash32.size());
    if (!request.wrapped_sig->empty()) {
        hasher.Write(request.wrapped_sig->data(), request.wrapped_sig->size());
    }
    if (!request.pubkey->empty()) {
        hasher.Write(request.pubkey->data(), request.pubkey->size());
    }
    if (!request.script_code->empty()) {
        hasher.Write(request.script_code->data(), request.script_code->size());
    }
    hasher.Finalize(digest.data());
    return digest;
}

MLDSA65BackendAdapterResult TranslateMLDSA65ExternalBackendResultCode(uint8_t result_code)
{
    if (result_code == MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_VERIFIED) {
        return MLDSA65BackendAdapterResult::VERIFIED;
    }
    if (result_code == MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    return MLDSA65BackendAdapterResult::UNAVAILABLE;
}

MLDSA65BackendAdapterResult VerifyMLDSA65ExternalBackendAdapter(const std::vector<unsigned char>& wrapped_sig,
                                                                const std::vector<unsigned char>& vchPubKey,
                                                                const CScript& scriptCode)
{
    if (!MLDSA65ExternalBackendBridgeReady()) {
        return MLDSA65BackendAdapterResult::UNAVAILABLE;
    }

    MLDSA65WrappedSigView wrapped_sig_view;
    if (!ParseMLDSA65WrappedSignature(wrapped_sig, &wrapped_sig_view)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    MLDSA65PubKeyView pubkey_view;
    if (!ParseMLDSA65PubKey(vchPubKey, &pubkey_view)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    if (scriptCode.empty()) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    if (!MLDSA65ExternalBackendRequestSizesSupported(
            wrapped_sig.size(),
            vchPubKey.size(),
            wrapped_sig_view.der_sig_size,
            pubkey_view.payload_size)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }

    MLDSA65ExternalBackendRequest request{
        MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION,
        MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE,
        MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1,
        MLDSA65_EXTERNAL_BACKEND_REQUEST_MAGIC,
        MLDSA65_EXTERNAL_BACKEND_REQUEST_SHAPE_HASH,
        MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID,
        &wrapped_sig,
        &vchPubKey,
        &scriptCode,
        wrapped_sig_view.der_sig_offset,
        wrapped_sig_view.der_sig_size,
        pubkey_view.payload_offset,
        pubkey_view.payload_size,
        wrapped_sig_view.sighash_type,
        pubkey_view.is_compressed,
        MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG,
        ComputeExternalBackendPrehashedSighash(scriptCode, wrapped_sig_view.sighash_type),
        std::array<unsigned char, 32>{},
    };

    if (!MLDSA65ExternalBackendRequestPointersSupported(request)) {
        return MLDSA65BackendAdapterResult::REJECTED;
    }
    request.request_content_digest32 = ComputeMLDSA65ExternalBackendRequestContentDigest(request);

    if (g_mldsa65_external_backend_request_observer != nullptr) {
        g_mldsa65_external_backend_request_observer(request);
        if (request.request_content_digest32 != ComputeMLDSA65ExternalBackendRequestContentDigest(request)) {
            return MLDSA65BackendAdapterResult::REJECTED;
        }
    }

    if (g_mldsa65_external_backend_result_code_verifier != nullptr) {
        return TranslateMLDSA65ExternalBackendResultCode(g_mldsa65_external_backend_result_code_verifier(request));
    }

    if (g_mldsa65_external_backend_verifier != nullptr) {
        return g_mldsa65_external_backend_verifier(wrapped_sig, vchPubKey, scriptCode);
    }

    const MLDSA65BackendAdapterResult real_api_result =
        VerifyMLDSA65ExternalBackendViaApi(request);
    if (real_api_result != MLDSA65BackendAdapterResult::UNAVAILABLE) {
        return real_api_result;
    }

    return MLDSA65BackendAdapterResult::UNAVAILABLE;
}

void SetMLDSA65ExternalBackendVerifierForTesting(MLDSA65NativeBackendVerifier verifier)
{
    g_mldsa65_external_backend_verifier = verifier;
}

void ResetMLDSA65ExternalBackendVerifierForTesting()
{
    g_mldsa65_external_backend_verifier = nullptr;
}

void SetMLDSA65ExternalBackendRequestObserverForTesting(MLDSA65ExternalBackendRequestObserver observer)
{
    g_mldsa65_external_backend_request_observer = observer;
}

void ResetMLDSA65ExternalBackendRequestObserverForTesting()
{
    g_mldsa65_external_backend_request_observer = nullptr;
}

void SetMLDSA65ExternalBackendResultCodeVerifierForTesting(MLDSA65ExternalBackendResultCodeVerifier verifier)
{
    g_mldsa65_external_backend_result_code_verifier = verifier;
}

void ResetMLDSA65ExternalBackendResultCodeVerifierForTesting()
{
    g_mldsa65_external_backend_result_code_verifier = nullptr;
}

void SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(MLDSA65NativeBackendBindingFactory factory)
{
    g_mldsa65_native_default_binding_factory = factory;
}

void ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting()
{
    g_mldsa65_native_default_binding_factory = nullptr;
}

} // namespace codequantum
