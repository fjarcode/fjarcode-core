#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze getcodequantuminfo RPC help contract."""

from test_framework.test_framework import BitcoinTestFramework


class RpcCodeQuantumInfoHelpContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "regtest"
        self.setup_clean_chain = True

    def run_test(self):
        help_index = self.nodes[0].help()
        assert "getcodequantuminfo" in help_index

        help_text = self.nodes[0].help("getcodequantuminfo")

        required_fragments = [
            "getcodequantuminfo",
            "Returns Code Quantum runtime status and currently active registry/budget profile.",
            '"enabled"',
            '"mode_wrapped_ecdsa"',
            '"algorithms"',
            '"wrapped_ecdsa_der"',
            '"sha3_256t"',
            '"mldsa_65"',
            '"active_algorithms"',
            '"capabilities"',
            '"mldsa_65_runtime_enabled"',
            '"mldsa_65_native_verify_available"',
            '"mldsa_65_verify_state"',
            '"mldsa_65_native_signing_available"',
            '"code_quantum_signing_disabled"',
            '"code_quantum_signing_verify_only"',
            '"code_quantum_signing_enabled"',
            '"code_quantum_signing_state"',
            '"external_backend_scaffold_enabled"',
            '"external_backend_header_detected"',
            '"external_backend_verify_api_declared"',
            '"external_backend_verify_linked"',
            '"external_backend_bridge_ready"',
            '"limits"',
            '"max_wrapped_sig_size"',
            '"max_envelope_size"',
            '"policy"',
            '"chain"',
            '"genesis"',
            '"hash"',
            '"merkle_root"',
            '"time"',
            '"nonce"',
            '"bits"',
            '"version"',
            '"reward_sats"',
            "Genesis/block0 profile for the active chain.",
            "Genesis block hash.",
            "Genesis block merkle root.",
            "Genesis block timestamp (nTime).",
            "Genesis block nonce (nNonce).",
            "Genesis block compact target (nBits).",
            "Genesis block version (nVersion).",
            "Genesis coinbase reward in satoshis.",
            '"default_consensus_block_size"',
            '"pow_target_spacing"',
            '"pow_target_spacing_sha3"',
            '"sha3_height"',
            '"sha3_version_bit"',
            '"hard_fork_height"',
            '"checkpoint_height"',
            '"activation_matrix"',
            '"fjarcode"',
            '"uahf"',
            '"daa"',
            '"magnetic_anomaly"',
            '"graviton"',
            '"phonon"',
            '"axion"',
            '"upgrade8"',
            '"upgrade9"',
            '"upgrade10"',
            '"upgrade11"',
            '"upgrade12"',
            "FJAR activation-height matrix for consensus feature gates.",
            "Base FJARCODE activation height.",
            "UAHF activation height.",
            "Difficulty adjustment activation height.",
            "Magnetic Anomaly activation height.",
            "Graviton activation height.",
            "Phonon activation height.",
            "Axion activation height.",
            "Upgrade8 activation height.",
            "Upgrade9 activation height.",
            "Upgrade10 activation height.",
            "Upgrade11 activation height.",
            "Upgrade12 activation height.",
            '"segwit_height"',
            '"segwit_disabled"',
            '"taproot_start_time"',
            '"taproot_disabled"',
            "Examples:",
        ]

        for fragment in required_fragments:
            assert fragment in help_text, f"Missing help fragment: {fragment}"


if __name__ == "__main__":
    RpcCodeQuantumInfoHelpContractTest(__file__).main()
