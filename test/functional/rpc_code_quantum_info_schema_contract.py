#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze getcodequantuminfo JSON schema contract (keys + value types)."""

from test_framework.cq_schema import assert_exact_keys, assert_type
from test_framework.test_framework import BitcoinTestFramework


class RpcCodeQuantumInfoSchemaContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "regtest"
        self.setup_clean_chain = True

    def run_test(self):
        info = self.nodes[0].getcodequantuminfo()

        assert_exact_keys(
            info,
            ["enabled", "mode_wrapped_ecdsa", "algorithms", "active_algorithms", "capabilities", "limits", "policy"],
            "root",
        )
        assert_type(info["enabled"], bool, "root.enabled")
        assert_type(info["mode_wrapped_ecdsa"], int, "root.mode_wrapped_ecdsa")

        assert_exact_keys(
            info["algorithms"],
            ["wrapped_ecdsa_der", "sha3_256t", "mldsa_65"],
            "root.algorithms",
        )
        assert_type(info["algorithms"]["wrapped_ecdsa_der"], int, "root.algorithms.wrapped_ecdsa_der")
        assert_type(info["algorithms"]["sha3_256t"], int, "root.algorithms.sha3_256t")
        assert_type(info["algorithms"]["mldsa_65"], int, "root.algorithms.mldsa_65")

        assert_type(info["active_algorithms"], list, "root.active_algorithms")
        for idx, algorithm_id in enumerate(info["active_algorithms"]):
            assert_type(algorithm_id, int, f"root.active_algorithms[{idx}]")

        assert_exact_keys(
            info["capabilities"],
            [
                "mldsa_65_runtime_enabled",
                "mldsa_65_native_verify_available",
                "mldsa_65_verify_state",
                "mldsa_65_native_signing_available",
                "code_quantum_signing_disabled",
                "code_quantum_signing_verify_only",
                "code_quantum_signing_enabled",
                "code_quantum_signing_state",
                "external_backend_scaffold_enabled",
                "external_backend_header_detected",
                "external_backend_verify_api_declared",
                "external_backend_verify_linked",
                "external_backend_bridge_ready",
            ],
            "root.capabilities",
        )
        assert_type(info["capabilities"]["mldsa_65_runtime_enabled"], bool, "root.capabilities.mldsa_65_runtime_enabled")
        assert_type(info["capabilities"]["mldsa_65_native_verify_available"], bool, "root.capabilities.mldsa_65_native_verify_available")
        assert_type(info["capabilities"]["mldsa_65_verify_state"], str, "root.capabilities.mldsa_65_verify_state")
        assert_type(info["capabilities"]["mldsa_65_native_signing_available"], bool, "root.capabilities.mldsa_65_native_signing_available")
        assert_type(info["capabilities"]["code_quantum_signing_disabled"], bool, "root.capabilities.code_quantum_signing_disabled")
        assert_type(info["capabilities"]["code_quantum_signing_verify_only"], bool, "root.capabilities.code_quantum_signing_verify_only")
        assert_type(info["capabilities"]["code_quantum_signing_enabled"], bool, "root.capabilities.code_quantum_signing_enabled")
        assert_type(info["capabilities"]["code_quantum_signing_state"], str, "root.capabilities.code_quantum_signing_state")
        assert_type(info["capabilities"]["external_backend_scaffold_enabled"], bool, "root.capabilities.external_backend_scaffold_enabled")
        assert_type(info["capabilities"]["external_backend_header_detected"], bool, "root.capabilities.external_backend_header_detected")
        assert_type(info["capabilities"]["external_backend_verify_api_declared"], bool, "root.capabilities.external_backend_verify_api_declared")
        assert_type(info["capabilities"]["external_backend_verify_linked"], bool, "root.capabilities.external_backend_verify_linked")
        assert_type(info["capabilities"]["external_backend_bridge_ready"], bool, "root.capabilities.external_backend_bridge_ready")

        assert_exact_keys(
            info["limits"],
            ["max_wrapped_sig_size", "max_envelope_size"],
            "root.limits",
        )
        assert_type(info["limits"]["max_wrapped_sig_size"], int, "root.limits.max_wrapped_sig_size")
        assert_type(info["limits"]["max_envelope_size"], int, "root.limits.max_envelope_size")

        policy = info["policy"]
        assert_exact_keys(
            policy,
            [
                "chain",
                "genesis",
                "default_consensus_block_size",
                "pow_target_spacing",
                "pow_target_spacing_sha3",
                "sha3_height",
                "sha3_version_bit",
                "hard_fork_height",
                "checkpoint_height",
                "activation_matrix",
                "segwit_height",
                "segwit_disabled",
                "taproot_start_time",
                "taproot_disabled",
            ],
            "root.policy",
        )
        assert_type(policy["chain"], str, "root.policy.chain")
        assert_type(policy["default_consensus_block_size"], int, "root.policy.default_consensus_block_size")
        assert_type(policy["pow_target_spacing"], int, "root.policy.pow_target_spacing")
        assert_type(policy["pow_target_spacing_sha3"], int, "root.policy.pow_target_spacing_sha3")
        assert_type(policy["sha3_height"], int, "root.policy.sha3_height")
        assert_type(policy["sha3_version_bit"], int, "root.policy.sha3_version_bit")
        assert_type(policy["hard_fork_height"], int, "root.policy.hard_fork_height")
        assert_type(policy["checkpoint_height"], int, "root.policy.checkpoint_height")
        assert_type(policy["segwit_height"], int, "root.policy.segwit_height")
        assert_type(policy["segwit_disabled"], bool, "root.policy.segwit_disabled")
        assert_type(policy["taproot_start_time"], int, "root.policy.taproot_start_time")
        assert_type(policy["taproot_disabled"], bool, "root.policy.taproot_disabled")

        assert_exact_keys(
            policy["genesis"],
            ["hash", "merkle_root", "time", "nonce", "bits", "version", "reward_sats"],
            "root.policy.genesis",
        )
        assert_type(policy["genesis"]["hash"], str, "root.policy.genesis.hash")
        assert_type(policy["genesis"]["merkle_root"], str, "root.policy.genesis.merkle_root")
        assert_type(policy["genesis"]["time"], int, "root.policy.genesis.time")
        assert_type(policy["genesis"]["nonce"], int, "root.policy.genesis.nonce")
        assert_type(policy["genesis"]["bits"], int, "root.policy.genesis.bits")
        assert_type(policy["genesis"]["version"], int, "root.policy.genesis.version")
        assert_type(policy["genesis"]["reward_sats"], int, "root.policy.genesis.reward_sats")

        assert_exact_keys(
            policy["activation_matrix"],
            [
                "fjarcode",
                "uahf",
                "daa",
                "magnetic_anomaly",
                "graviton",
                "phonon",
                "axion",
                "upgrade8",
                "upgrade9",
                "upgrade10",
                "upgrade11",
                "upgrade12",
            ],
            "root.policy.activation_matrix",
        )
        for field, value in policy["activation_matrix"].items():
            assert_type(value, int, f"root.policy.activation_matrix.{field}")


if __name__ == "__main__":
    RpcCodeQuantumInfoSchemaContractTest(__file__).main()
