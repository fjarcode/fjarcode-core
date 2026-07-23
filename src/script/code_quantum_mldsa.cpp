// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/code_quantum_mldsa.h>

#include <script/code_quantum_mldsa_backend.h>

#include <script/code_quantum_params.h>

#include <array>

namespace codequantum {

namespace {

MLDSA65BackendVerifier g_mldsa65_backend_verifier{nullptr};
MLDSA65BackendResultVerifier g_mldsa65_backend_result_verifier{nullptr};

inline void SetWrappedSigParseError(MLDSA65WrappedSigParseError* out_error,
                                    MLDSA65WrappedSigParseError error)
{
    if (out_error != nullptr) {
        *out_error = error;
    }
}

inline void SetPubKeyParseError(MLDSA65PubKeyParseError* out_error,
                                MLDSA65PubKeyParseError error)
{
    if (out_error != nullptr) {
        *out_error = error;
    }
}

inline void SetVerifyError(MLDSA65VerifyError* out_error,
                           MLDSA65VerifyError error)
{
    if (out_error != nullptr) {
        *out_error = error;
    }
}

constexpr std::array<unsigned char, 32> SECP256K1_HALF_ORDER{{
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
}};

bool IsLowSValue(const std::vector<unsigned char>& wrapped_sig, size_t s_offset, size_t s_len)
{
    if (s_len == 0 || s_len > 33) {
        return false;
    }

    if (s_len < 32) {
        return true;
    }

    size_t scalar_offset{s_offset};
    if (s_len == 33) {
        if (wrapped_sig[s_offset] != 0x00) {
            return false;
        }
        scalar_offset = s_offset + 1;
    }

    for (size_t i = 0; i < SECP256K1_HALF_ORDER.size(); ++i) {
        const unsigned char lhs = wrapped_sig[scalar_offset + i];
        const unsigned char rhs = SECP256K1_HALF_ORDER[i];
        if (lhs < rhs) {
            return true;
        }
        if (lhs > rhs) {
            return false;
        }
    }

    return true;
}

MLDSA65BackendAdapterResult VerifyMLDSA65BackendAdapterResult(const std::vector<unsigned char>& wrapped_sig,
                                                              const std::vector<unsigned char>& vchPubKey,
                                                              const CScript& scriptCode)
{
    return VerifyMLDSA65BackendAdapterResultImpl(wrapped_sig, vchPubKey, scriptCode);
}

} // namespace

bool ParseMLDSA65WrappedSignatureDetailed(const std::vector<unsigned char>& wrapped_sig,
                                          MLDSA65WrappedSigView* out_view,
                                          MLDSA65WrappedSigParseError* out_error)
{
    if (wrapped_sig.empty() || wrapped_sig.size() > MAX_WRAPPED_SIG_SIZE) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::EMPTY_OR_OVERSIZE);
        return false;
    }
    if (wrapped_sig.size() < 9) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::TOO_SHORT);
        return false;
    }
    if (wrapped_sig[0] != 0x30) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_SEQUENCE_TAG);
        return false;
    }
    const size_t der_sig_size{static_cast<size_t>(wrapped_sig[1]) + 2};
    if (der_sig_size + 1 != wrapped_sig.size()) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_DER_TOTAL_LENGTH);
        return false;
    }

    // Enforce strict DER integer layout for the two scalar components.
    if (wrapped_sig[2] != 0x02) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_R_TAG);
        return false;
    }
    const size_t r_len{static_cast<size_t>(wrapped_sig[3])};
    if (r_len == 0) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_R_LENGTH);
        return false;
    }
    const size_t r_offset{4};
    const size_t s_tag_offset{r_offset + r_len};
    if (s_tag_offset + 2 > der_sig_size) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_RS_BOUNDARY);
        return false;
    }
    if (wrapped_sig[s_tag_offset] != 0x02) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_S_TAG);
        return false;
    }
    const size_t s_len{static_cast<size_t>(wrapped_sig[s_tag_offset + 1])};
    if (s_len == 0) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_S_LENGTH);
        return false;
    }
    const size_t s_offset{s_tag_offset + 2};
    if (s_offset + s_len != der_sig_size) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::BAD_RS_BOUNDARY);
        return false;
    }

    const unsigned char r_first = wrapped_sig[r_offset];
    if (r_first & 0x80) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::NEGATIVE_R);
        return false;
    }
    const bool r_is_minimally_encoded = !(r_len > 1 && r_first == 0x00 && !(wrapped_sig[r_offset + 1] & 0x80));
    if (!r_is_minimally_encoded) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::NON_MINIMAL_R);
        return false;
    }

    const unsigned char s_first = wrapped_sig[s_offset];
    if (s_first & 0x80) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::NEGATIVE_S);
        return false;
    }
    const bool s_is_minimally_encoded = !(s_len > 1 && s_first == 0x00 && !(wrapped_sig[s_offset + 1] & 0x80));
    if (!s_is_minimally_encoded) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::NON_MINIMAL_S);
        return false;
    }
    const bool s_is_low = IsLowSValue(wrapped_sig, s_offset, s_len);
    if (!s_is_low) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::HIGH_S);
        return false;
    }

    if (wrapped_sig.back() == 0x00) {
        SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::ZERO_HASHTYPE);
        return false;
    }

    if (out_view != nullptr) {
        out_view->der_sig_offset = 0;
        out_view->der_sig_size = der_sig_size;
        out_view->r_offset = r_offset;
        out_view->r_size = r_len;
        out_view->r_is_minimally_encoded = r_is_minimally_encoded;
        out_view->s_offset = s_offset;
        out_view->s_size = s_len;
        out_view->s_is_minimally_encoded = s_is_minimally_encoded;
        out_view->s_is_low = s_is_low;
        out_view->sighash_offset = der_sig_size;
        out_view->sighash_type = wrapped_sig.back();
    }

    SetWrappedSigParseError(out_error, MLDSA65WrappedSigParseError::OK);

    return true;
}

bool ParseMLDSA65WrappedSignature(const std::vector<unsigned char>& wrapped_sig,
                                  MLDSA65WrappedSigView* out_view)
{
    return ParseMLDSA65WrappedSignatureDetailed(wrapped_sig, out_view, nullptr);
}

bool ParseMLDSA65PubKeyDetailed(const std::vector<unsigned char>& vchPubKey,
                                MLDSA65PubKeyView* out_view,
                                MLDSA65PubKeyParseError* out_error)
{
    if (vchPubKey.empty()) {
        SetPubKeyParseError(out_error, MLDSA65PubKeyParseError::EMPTY);
        return false;
    }
    if (vchPubKey.size() > MAX_PUBKEY_SIZE) {
        SetPubKeyParseError(out_error, MLDSA65PubKeyParseError::OVERSIZE);
        return false;
    }
    const unsigned char pubkey_prefix = vchPubKey[0];
    const bool is_compressed = (vchPubKey.size() == 33) && (pubkey_prefix == 0x02 || pubkey_prefix == 0x03);
    const bool is_uncompressed = (vchPubKey.size() == 65) && (pubkey_prefix == 0x04);
    if (!is_compressed && !is_uncompressed) {
        SetPubKeyParseError(out_error, MLDSA65PubKeyParseError::INVALID_FORMAT);
        return false;
    }

    if (out_view != nullptr) {
        out_view->is_compressed = is_compressed;
        out_view->payload_offset = 1;
        out_view->payload_size = vchPubKey.size() - 1;
        out_view->prefix = pubkey_prefix;
    }

    SetPubKeyParseError(out_error, MLDSA65PubKeyParseError::OK);

    return true;
}

bool ParseMLDSA65PubKey(const std::vector<unsigned char>& vchPubKey,
                        MLDSA65PubKeyView* out_view)
{
    return ParseMLDSA65PubKeyDetailed(vchPubKey, out_view, nullptr);
}

bool IsStructurallyValidMLDSA65WrappedSignature(const std::vector<unsigned char>& wrapped_sig)
{
    return ParseMLDSA65WrappedSignature(wrapped_sig, nullptr);
}

bool IsStructurallyValidMLDSA65PubKey(const std::vector<unsigned char>& vchPubKey)
{
    return ParseMLDSA65PubKey(vchPubKey, nullptr);
}

bool VerifyMLDSA65SignatureDetailed(const std::vector<unsigned char>& wrapped_sig,
                                    const std::vector<unsigned char>& vchPubKey,
                                    const CScript& scriptCode,
                                    MLDSA65VerifyError* out_error)
{
    if (!IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig)) {
        SetVerifyError(out_error, MLDSA65VerifyError::WRAPPED_SIG_INVALID);
        return false;
    }
    if (!IsStructurallyValidMLDSA65PubKey(vchPubKey)) {
        SetVerifyError(out_error, MLDSA65VerifyError::PUBKEY_INVALID);
        return false;
    }

    if (scriptCode.empty()) {
        SetVerifyError(out_error, MLDSA65VerifyError::EMPTY_SCRIPT_CODE);
        return false;
    }

    if (g_mldsa65_backend_verifier != nullptr && g_mldsa65_backend_verifier(wrapped_sig, vchPubKey, scriptCode)) {
        SetVerifyError(out_error, MLDSA65VerifyError::OK);
        return true;
    }

    if (g_mldsa65_backend_result_verifier != nullptr) {
        const MLDSA65BackendAdapterResult hook_result =
            g_mldsa65_backend_result_verifier(wrapped_sig, vchPubKey, scriptCode);
        if (hook_result == MLDSA65BackendAdapterResult::VERIFIED) {
            SetVerifyError(out_error, MLDSA65VerifyError::OK);
            return true;
        }
        if (hook_result == MLDSA65BackendAdapterResult::REJECTED) {
            SetVerifyError(out_error, MLDSA65VerifyError::BACKEND_REJECTED);
            return false;
        }
        if (hook_result == MLDSA65BackendAdapterResult::UNAVAILABLE) {
            // Fall through to adapter path until a production backend is wired.
        }
    }

    const MLDSA65BackendAdapterResult adapter_result =
        VerifyMLDSA65BackendAdapterResult(wrapped_sig, vchPubKey, scriptCode);
    if (adapter_result == MLDSA65BackendAdapterResult::VERIFIED) {
        SetVerifyError(out_error, MLDSA65VerifyError::OK);
        return true;
    }
    if (adapter_result == MLDSA65BackendAdapterResult::REJECTED) {
        SetVerifyError(out_error, MLDSA65VerifyError::BACKEND_REJECTED);
        return false;
    }

    // Placeholder: cryptographic ML-DSA-65 verification is intentionally not wired yet.
    SetVerifyError(out_error, MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED);
    return false;
}

bool VerifyMLDSA65Signature(const std::vector<unsigned char>& wrapped_sig,
                            const std::vector<unsigned char>& vchPubKey,
                            const CScript& scriptCode)
{
    return VerifyMLDSA65SignatureDetailed(wrapped_sig, vchPubKey, scriptCode, nullptr);
}

void SetMLDSA65BackendVerifierForTesting(MLDSA65BackendVerifier verifier)
{
    g_mldsa65_backend_verifier = verifier;
}

void ResetMLDSA65BackendVerifierForTesting()
{
    g_mldsa65_backend_verifier = nullptr;
}

void SetMLDSA65BackendResultVerifierForTesting(MLDSA65BackendResultVerifier verifier)
{
    g_mldsa65_backend_result_verifier = verifier;
}

void ResetMLDSA65BackendResultVerifierForTesting()
{
    g_mldsa65_backend_result_verifier = nullptr;
}

} // namespace codequantum
