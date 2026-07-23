// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_H
#define BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_H

#include <script/script.h>
#include <script/code_quantum_mldsa_backend.h>

#include <cstddef>
#include <vector>

namespace codequantum {

enum class MLDSA65WrappedSigParseError : uint8_t {
    OK = 0,
    EMPTY_OR_OVERSIZE,
    TOO_SHORT,
    BAD_SEQUENCE_TAG,
    BAD_DER_TOTAL_LENGTH,
    BAD_R_TAG,
    BAD_R_LENGTH,
    BAD_S_TAG,
    BAD_S_LENGTH,
    BAD_RS_BOUNDARY,
    NEGATIVE_R,
    NON_MINIMAL_R,
    NEGATIVE_S,
    NON_MINIMAL_S,
    HIGH_S,
    ZERO_HASHTYPE,
};

enum class MLDSA65PubKeyParseError : uint8_t {
    OK = 0,
    EMPTY,
    OVERSIZE,
    INVALID_FORMAT,
};

enum class MLDSA65VerifyError : uint8_t {
    OK = 0,
    WRAPPED_SIG_INVALID,
    PUBKEY_INVALID,
    EMPTY_SCRIPT_CODE,
    BACKEND_REJECTED,
    BACKEND_NOT_IMPLEMENTED,
};

struct MLDSA65WrappedSigView {
    size_t der_sig_offset;
    size_t der_sig_size;
    size_t r_offset;
    size_t r_size;
    bool r_is_minimally_encoded;
    size_t s_offset;
    size_t s_size;
    bool s_is_minimally_encoded;
    bool s_is_low;
    size_t sighash_offset;
    unsigned char sighash_type;
};

struct MLDSA65PubKeyView {
    bool is_compressed;
    size_t payload_offset;
    size_t payload_size;
    unsigned char prefix;
};

using MLDSA65BackendVerifier = bool (*)(const std::vector<unsigned char>& wrapped_sig,
                                        const std::vector<unsigned char>& vchPubKey,
                                        const CScript& scriptCode);
using MLDSA65BackendResultVerifier = MLDSA65BackendAdapterResult (*)(const std::vector<unsigned char>& wrapped_sig,
                                                                     const std::vector<unsigned char>& vchPubKey,
                                                                     const CScript& scriptCode);

bool ParseMLDSA65WrappedSignature(const std::vector<unsigned char>& wrapped_sig,
                                  MLDSA65WrappedSigView* out_view);
bool ParseMLDSA65WrappedSignatureDetailed(const std::vector<unsigned char>& wrapped_sig,
                                          MLDSA65WrappedSigView* out_view,
                                          MLDSA65WrappedSigParseError* out_error);
bool ParseMLDSA65PubKey(const std::vector<unsigned char>& vchPubKey,
                        MLDSA65PubKeyView* out_view);
bool ParseMLDSA65PubKeyDetailed(const std::vector<unsigned char>& vchPubKey,
                                MLDSA65PubKeyView* out_view,
                                MLDSA65PubKeyParseError* out_error);

// Structural parser-only contract for staged ML-DSA-65 rollout.
bool IsStructurallyValidMLDSA65WrappedSignature(const std::vector<unsigned char>& wrapped_sig);
bool IsStructurallyValidMLDSA65PubKey(const std::vector<unsigned char>& vchPubKey);

// Placeholder verifier for ML-DSA-65 envelopes. The cryptographic backend is
// intentionally not wired yet; this function currently returns false.
bool VerifyMLDSA65Signature(const std::vector<unsigned char>& wrapped_sig,
                            const std::vector<unsigned char>& vchPubKey,
                            const CScript& scriptCode);
bool VerifyMLDSA65SignatureDetailed(const std::vector<unsigned char>& wrapped_sig,
                                    const std::vector<unsigned char>& vchPubKey,
                                    const CScript& scriptCode,
                                    MLDSA65VerifyError* out_error);

// Temporary backend hook to integrate and test ML-DSA verifier wiring before
// final production backend plumbing lands.
void SetMLDSA65BackendVerifierForTesting(MLDSA65BackendVerifier verifier);
void ResetMLDSA65BackendVerifierForTesting();
void SetMLDSA65BackendResultVerifierForTesting(MLDSA65BackendResultVerifier verifier);
void ResetMLDSA65BackendResultVerifierForTesting();

} // namespace codequantum

#endif // BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_H
