// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_CODE_QUANTUM_PARAMS_H
#define BITCOIN_SCRIPT_CODE_QUANTUM_PARAMS_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace codequantum {

inline constexpr size_t MAX_WRAPPED_SIG_SIZE{73};
inline constexpr size_t MAX_ENVELOPE_SIZE{79};
inline constexpr size_t MAX_PUBKEY_SIZE{65};
inline constexpr size_t MAX_STACK_PUSH_TOTAL{MAX_ENVELOPE_SIZE + MAX_PUBKEY_SIZE};
inline constexpr uint32_t VERIFY_COST_LIMIT{106};

inline constexpr uint8_t MODE_V1_WRAPPED_ECDSA{0};
inline constexpr uint8_t MODE_V1_RESERVED_EXTENSION_START{1};

inline constexpr uint8_t ALGORITHM_V1_WRAPPED_ECDSA_DER{0};
inline constexpr uint8_t ALGORITHM_V1_SHA3_256T{1};
inline constexpr uint8_t ALGORITHM_V1_ML_DSA_65{2};

inline constexpr std::array<uint8_t, 1> SUPPORTED_MODES{
    MODE_V1_WRAPPED_ECDSA,
};

inline constexpr std::array<uint8_t, 3> MODE_V1_KNOWN_ALGORITHMS{
    ALGORITHM_V1_WRAPPED_ECDSA_DER,
    ALGORITHM_V1_SHA3_256T,
    ALGORITHM_V1_ML_DSA_65,
};

inline constexpr std::array<uint8_t, 2> MODE_V1_ACTIVE_ALGORITHMS{
    ALGORITHM_V1_WRAPPED_ECDSA_DER,
    ALGORITHM_V1_SHA3_256T,
};

// Emergency safety gate: keep ML-DSA-65 reserved but inactive until
// deterministic backend behavior is guaranteed across all node builds.
inline constexpr bool ML_DSA_65_RUNTIME_ENABLED{false};

} // namespace codequantum

#endif // BITCOIN_SCRIPT_CODE_QUANTUM_PARAMS_H