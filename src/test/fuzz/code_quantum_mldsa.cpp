// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/code_quantum_mldsa.h>
#include <script/code_quantum_params.h>
#include <script/script.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using codequantum::MLDSA65PubKeyParseError;
using codequantum::MLDSA65PubKeyView;
using codequantum::MLDSA65VerifyError;
using codequantum::MLDSA65WrappedSigParseError;
using codequantum::MLDSA65WrappedSigView;

void AssertWrappedSigInvariants(const std::vector<unsigned char>& wrapped_sig)
{
    MLDSA65WrappedSigView detailed_view{};
    MLDSA65WrappedSigParseError parse_error{MLDSA65WrappedSigParseError::OK};
    const bool detailed_ok = codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig, &detailed_view, &parse_error);

    MLDSA65WrappedSigView simple_view{};
    const bool simple_ok = codequantum::ParseMLDSA65WrappedSignature(wrapped_sig, &simple_view);

    assert(detailed_ok == simple_ok);
    assert(codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig) == detailed_ok);

    if (detailed_ok) {
        assert(parse_error == MLDSA65WrappedSigParseError::OK);
        assert(detailed_view.der_sig_offset == 0);
        assert(detailed_view.der_sig_size + 1 == wrapped_sig.size());
        assert(detailed_view.sighash_offset + 1 == wrapped_sig.size());
        assert(detailed_view.r_size > 0);
        assert(detailed_view.s_size > 0);
        assert(detailed_view.r_offset + detailed_view.r_size <= detailed_view.der_sig_size);
        assert(detailed_view.s_offset + detailed_view.s_size == detailed_view.der_sig_size);
        assert(detailed_view.sighash_type != 0x00);
    } else {
        assert(parse_error != MLDSA65WrappedSigParseError::OK);
    }
}

void AssertPubKeyInvariants(const std::vector<unsigned char>& pubkey)
{
    MLDSA65PubKeyView detailed_view{};
    MLDSA65PubKeyParseError parse_error{MLDSA65PubKeyParseError::OK};
    const bool detailed_ok = codequantum::ParseMLDSA65PubKeyDetailed(pubkey, &detailed_view, &parse_error);

    MLDSA65PubKeyView simple_view{};
    const bool simple_ok = codequantum::ParseMLDSA65PubKey(pubkey, &simple_view);

    assert(detailed_ok == simple_ok);
    assert(codequantum::IsStructurallyValidMLDSA65PubKey(pubkey) == detailed_ok);

    if (detailed_ok) {
        assert(parse_error == MLDSA65PubKeyParseError::OK);
        assert(detailed_view.payload_offset == 1);
        assert(detailed_view.payload_size + 1 == pubkey.size());
        assert((pubkey.size() == 33 && (detailed_view.prefix == 0x02 || detailed_view.prefix == 0x03)) ||
               (pubkey.size() == 65 && detailed_view.prefix == 0x04));
    } else {
        assert(parse_error != MLDSA65PubKeyParseError::OK);
    }
}

void AssertVerifyInvariants(const std::vector<unsigned char>& wrapped_sig,
                            const std::vector<unsigned char>& pubkey,
                            const CScript& script_code)
{
    MLDSA65VerifyError verify_error{MLDSA65VerifyError::OK};
    const bool verified_detailed = codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig, pubkey, script_code, &verify_error);
    const bool verified_simple = codequantum::VerifyMLDSA65Signature(wrapped_sig, pubkey, script_code);

    assert(verified_detailed == verified_simple);

    const bool wrapped_sig_valid = codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig);
    const bool pubkey_valid = codequantum::IsStructurallyValidMLDSA65PubKey(pubkey);

    if (!wrapped_sig_valid) {
        assert(!verified_detailed);
        assert(verify_error == MLDSA65VerifyError::WRAPPED_SIG_INVALID);
        return;
    }
    if (!pubkey_valid) {
        assert(!verified_detailed);
        assert(verify_error == MLDSA65VerifyError::PUBKEY_INVALID);
        return;
    }
    if (script_code.empty()) {
        assert(!verified_detailed);
        assert(verify_error == MLDSA65VerifyError::EMPTY_SCRIPT_CODE);
        return;
    }

    if (verified_detailed) {
        assert(verify_error == MLDSA65VerifyError::OK);
    } else {
        assert(verify_error == MLDSA65VerifyError::BACKEND_REJECTED || verify_error == MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED);
    }
}

std::vector<unsigned char> MutateVector(FuzzedDataProvider& fuzzed_data_provider, std::vector<unsigned char> value)
{
    const int op = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 3);
    if (op == 0 && !value.empty()) {
        const size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, value.size() - 1);
        value[idx] ^= fuzzed_data_provider.ConsumeIntegral<unsigned char>();
    } else if (op == 1) {
        value.push_back(fuzzed_data_provider.ConsumeIntegral<unsigned char>());
    } else if (op == 2 && !value.empty()) {
        const size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, value.size() - 1);
        value.erase(value.begin() + idx);
    } else if (!value.empty()) {
        const size_t idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, value.size() - 1);
        value[idx] = static_cast<unsigned char>(value[idx] + 1);
    }
    return value;
}

} // namespace

FUZZ_TARGET(code_quantum_mldsa)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    std::vector<unsigned char> wrapped_sig = ConsumeRandomLengthByteVector(fuzzed_data_provider);
    std::vector<unsigned char> pubkey = ConsumeRandomLengthByteVector(fuzzed_data_provider);
    std::vector<unsigned char> script_bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider);
    if (script_bytes.size() > codequantum::MAX_STACK_PUSH_TOTAL) {
        script_bytes.resize(codequantum::MAX_STACK_PUSH_TOTAL);
    }
    const CScript script_code{script_bytes.begin(), script_bytes.end()};

    AssertWrappedSigInvariants(wrapped_sig);
    AssertPubKeyInvariants(pubkey);
    AssertVerifyInvariants(wrapped_sig, pubkey, script_code);

    // Deterministic adversarial seeds: mutate structurally valid baseline vectors
    // to continuously pressure parser precedence and metadata handling.
    const std::vector<unsigned char> baseline_wrapped_sig{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
    };
    std::vector<unsigned char> baseline_pubkey(33, 0x01);
    baseline_pubkey[0] = 0x02;

    std::vector<unsigned char> mutated_sig = baseline_wrapped_sig;
    std::vector<unsigned char> mutated_pubkey = baseline_pubkey;

    const size_t mutation_rounds = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 8);
    for (size_t i = 0; i < mutation_rounds; ++i) {
        mutated_sig = MutateVector(fuzzed_data_provider, std::move(mutated_sig));
        mutated_pubkey = MutateVector(fuzzed_data_provider, std::move(mutated_pubkey));

        AssertWrappedSigInvariants(mutated_sig);
        AssertPubKeyInvariants(mutated_pubkey);
        AssertVerifyInvariants(mutated_sig, mutated_pubkey, script_code);
    }
}
