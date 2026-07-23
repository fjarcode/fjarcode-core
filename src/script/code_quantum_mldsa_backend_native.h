// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_NATIVE_H
#define BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_NATIVE_H

#include <script/code_quantum_mldsa_backend_provider.h>

#include <array>
#include <cstdint>

namespace codequantum {

using MLDSA65NativeBackendBindingFactory = MLDSA65NativeBackendBinding (*)();
constexpr uint32_t MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION{1};
constexpr uint32_t MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PREHASHED_SIGHASH{1U << 0};
constexpr uint32_t MLDSA65_EXTERNAL_BACKEND_CAPABILITY_DER_WRAPPED_SIGNATURE{1U << 1};
constexpr uint32_t MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE{
	MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PREHASHED_SIGHASH |
	MLDSA65_EXTERNAL_BACKEND_CAPABILITY_DER_WRAPPED_SIGNATURE};
constexpr uint32_t MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1{1};
constexpr std::array<unsigned char, 8> MLDSA65_EXTERNAL_BACKEND_REQUEST_MAGIC{
	'C', 'Q', 'M', 'L', 'D', 'S', 'A', '6'};
constexpr uint32_t MLDSA65_EXTERNAL_BACKEND_REQUEST_SHAPE_HASH{0x434d3651U};
constexpr std::array<unsigned char, 16> MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID{
	'C', 'Q', '-', 'M', 'L', 'D', 'S', 'A', '6', '5', '-', 'I', 'F', '-', 'v', '1'};
constexpr std::array<unsigned char, 13> MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG{
    'C', 'Q', '-', 'M', 'L', 'D', 'S', 'A', '6', '5', '-', 'v', '1'};
constexpr std::array<unsigned char, 12> MLDSA65_EXTERNAL_BACKEND_REQUEST_DIGEST_DOMAIN_TAG{
	'C', 'Q', '-', 'R', 'E', 'Q', '-', 'D', 'I', 'G', '-', '1'};
constexpr uint8_t MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_VERIFIED{0};
constexpr uint8_t MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED{1};
constexpr uint8_t MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_UNAVAILABLE{2};
constexpr size_t MLDSA65_EXTERNAL_BACKEND_MAX_WRAPPED_SIG_SIZE{73};
constexpr size_t MLDSA65_EXTERNAL_BACKEND_MAX_PUBKEY_SIZE{65};

struct MLDSA65ExternalBackendRequest {
	uint32_t request_version;
	uint32_t capability_flags;
	uint32_t capability_profile_id;
	std::array<unsigned char, 8> request_magic;
	uint32_t request_shape_hash;
	std::array<unsigned char, 16> external_backend_interface_id;
	const std::vector<unsigned char>* wrapped_sig;
	const std::vector<unsigned char>* pubkey;
	const CScript* script_code;
	size_t der_sig_offset;
	size_t der_sig_size;
	size_t pubkey_payload_offset;
	size_t pubkey_payload_size;
	unsigned char sighash_type;
	bool pubkey_is_compressed;
	std::array<unsigned char, 13> prehash_domain_tag;
	std::array<unsigned char, 32> prehashed_sighash32;
	std::array<unsigned char, 32> request_content_digest32;
};
using MLDSA65ExternalBackendRequestObserver = void (*)(const MLDSA65ExternalBackendRequest& request);
using MLDSA65ExternalBackendResultCodeVerifier = uint8_t (*)(const MLDSA65ExternalBackendRequest& request);
std::array<unsigned char, 32> ComputeMLDSA65ExternalBackendRequestContentDigest(const MLDSA65ExternalBackendRequest& request);

// Returns the default production-native binding for ML-DSA-65. The default
// implementation is intentionally empty until a concrete crypto backend is
// linked into this module.
MLDSA65NativeBackendBinding GetDefaultMLDSA65NativeBackendBinding();

// Build-time introspection hooks for external-backend integration scaffolding.
bool MLDSA65ExternalBackendScaffoldEnabled();
bool MLDSA65ExternalBackendHeaderDetected();
bool MLDSA65ExternalBackendBridgeReady();
bool MLDSA65ExternalBackendRequestVersionSupported(uint32_t request_version);
bool MLDSA65ExternalBackendCapabilitiesSupported(uint32_t capability_flags);
bool MLDSA65ExternalBackendCapabilityProfileSupported(uint32_t capability_profile_id);
bool MLDSA65ExternalBackendInterfaceIdSupported(const std::array<unsigned char, 16>& interface_id);
bool MLDSA65ExternalBackendResultCodeSupported(uint8_t result_code);
bool MLDSA65ExternalBackendRequestSizesSupported(size_t wrapped_sig_size,
												 size_t pubkey_size,
												 size_t der_sig_size,
												 size_t pubkey_payload_size);
bool MLDSA65ExternalBackendRequestPointersSupported(const MLDSA65ExternalBackendRequest& request);
MLDSA65BackendAdapterResult TranslateMLDSA65ExternalBackendResultCode(uint8_t result_code);
MLDSA65BackendAdapterResult VerifyMLDSA65ExternalBackendAdapter(const std::vector<unsigned char>& wrapped_sig,
                                                                const std::vector<unsigned char>& vchPubKey,
                                                                const CScript& scriptCode);

void SetMLDSA65ExternalBackendVerifierForTesting(MLDSA65NativeBackendVerifier verifier);
void ResetMLDSA65ExternalBackendVerifierForTesting();
void SetMLDSA65ExternalBackendRequestObserverForTesting(MLDSA65ExternalBackendRequestObserver observer);
void ResetMLDSA65ExternalBackendRequestObserverForTesting();
void SetMLDSA65ExternalBackendResultCodeVerifierForTesting(MLDSA65ExternalBackendResultCodeVerifier verifier);
void ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();

// Testing-only seam for freezing lazy-init provider behavior around default
// binding acquisition.
void SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(MLDSA65NativeBackendBindingFactory factory);
void ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();

} // namespace codequantum

#endif // BITCOIN_SCRIPT_CODE_QUANTUM_MLDSA_BACKEND_NATIVE_H
