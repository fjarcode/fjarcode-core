// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <script/code_quantum_mldsa.h>
#include <script/code_quantum_mldsa_backend_provider.h>
#include <script/script.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

static void CodeQuantumMLDSAVerifyRejectPathBench(benchmark::Bench& bench)
{
    // Each vector is malformed in a different way to stress parser rejection
    // cost and ensure deterministic reject-error precedence under load.
    const std::array<std::vector<unsigned char>, 6> wrapped_sig_vectors{{
        {},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x81, 0x01},
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00},
    }};

    const std::vector<unsigned char> compressed_pubkey(33, 0x02);
    const CScript script_code = CScript() << OP_1 << OP_1 << OP_EQUAL;

    size_t idx = 0;
    bench.batch(wrapped_sig_vectors.size()).run([&] {
        const auto& wrapped_sig = wrapped_sig_vectors[idx % wrapped_sig_vectors.size()];
        idx++;

        codequantum::MLDSA65VerifyError verify_error{codequantum::MLDSA65VerifyError::OK};
        const bool verified = codequantum::VerifyMLDSA65SignatureDetailed(
            wrapped_sig,
            compressed_pubkey,
            script_code,
            &verify_error);

        assert(!verified);
        assert(verify_error == codequantum::MLDSA65VerifyError::WRAPPED_SIG_INVALID);
    });
}

static void CodeQuantumMLDSASigningUnavailableBench(benchmark::Bench& bench)
{
    const std::vector<unsigned char> key_material(32, 0x11);
    const CScript script_code = CScript() << OP_1 << OP_2 << OP_ADD;
    constexpr unsigned char sighash_all{0x01};

    bench.run([&] {
        std::vector<unsigned char> wrapped_sig_out{0xaa, 0xbb, 0xcc};
        const auto result = codequantum::SignMLDSA65NativeBackend(
            key_material,
            script_code,
            sighash_all,
            wrapped_sig_out);

        assert(result == codequantum::MLDSA65NativeBackendSignResult::UNAVAILABLE ||
               result == codequantum::MLDSA65NativeBackendSignResult::REJECTED ||
               result == codequantum::MLDSA65NativeBackendSignResult::SIGNED);

        if (result != codequantum::MLDSA65NativeBackendSignResult::SIGNED) {
            assert(wrapped_sig_out.empty());
        }
    });
}

} // namespace

BENCHMARK(CodeQuantumMLDSAVerifyRejectPathBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(CodeQuantumMLDSASigningUnavailableBench, benchmark::PriorityLevel::HIGH);
