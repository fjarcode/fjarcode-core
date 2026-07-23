// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_H
#define BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_H

#include <script/script.h>

#include <cstdint>
#include <vector>

namespace codequantum {

enum class MLDSA65BackendAdapterResult : uint8_t {
    VERIFIED = 0,
    REJECTED,
    UNAVAILABLE,
};

// Crypto backend integration point for ML-DSA-65 signature verification.
// This currently returns false until real backend wiring is added.
MLDSA65BackendAdapterResult VerifyMLDSA65BackendAdapterResultImpl(const std::vector<unsigned char>& wrapped_sig,
                                                                  const std::vector<unsigned char>& vchPubKey,
                                                                  const CScript& scriptCode);

bool VerifyMLDSA65BackendAdapterImpl(const std::vector<unsigned char>& wrapped_sig,
                                     const std::vector<unsigned char>& vchPubKey,
                                     const CScript& scriptCode);

} // namespace codequantum

#endif // BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_H
