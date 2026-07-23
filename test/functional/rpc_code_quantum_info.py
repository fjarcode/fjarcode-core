#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getcodequantuminfo RPC output contract."""

from pathlib import Path
import re

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RpcCodeQuantumInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "regtest"
        self.setup_clean_chain = True

    def run_test(self):
        info = self.nodes[0].getcodequantuminfo()

        srcdir = Path(self.config["environment"]["SRCDIR"])
        params = (srcdir / "src" / "script" / "code_quantum_params.h").read_text(encoding="utf8")

        budget_match = re.search(
            r"MAX_WRAPPED_SIG_SIZE\{\s*(\d+)\s*\}.*MAX_ENVELOPE_SIZE\{\s*(\d+)\s*\}",
            params,
            re.MULTILINE | re.DOTALL,
        )
        if budget_match is None:
            raise AssertionError("Missing Code Quantum budget constants in code_quantum_params.h")
        max_wrapped_sig_size = int(budget_match.group(1))
        max_envelope_size = int(budget_match.group(2))

        registry_match = re.search(
            r"MODE_V1_WRAPPED_ECDSA\{\s*(\d+)\s*\}.*MODE_V1_RESERVED_EXTENSION_START\{\s*(\d+)\s*\}.*ALGORITHM_V1_WRAPPED_ECDSA_DER\{\s*(\d+)\s*\}.*ALGORITHM_V1_SHA3_256T\{\s*(\d+)\s*\}.*ALGORITHM_V1_ML_DSA_65\{\s*(\d+)\s*\}",
            params,
            re.MULTILINE | re.DOTALL,
        )
        if registry_match is None:
            raise AssertionError("Missing Code Quantum registry constants in code_quantum_params.h")
        mode_wrapped_ecdsa = int(registry_match.group(1))
        algorithm_wrapped_ecdsa_der = int(registry_match.group(3))
        algorithm_sha3_256t = int(registry_match.group(4))
        algorithm_mldsa_65 = int(registry_match.group(5))

        mldsa_runtime_match = re.search(
            r"ML_DSA_65_RUNTIME_ENABLED\{\s*(true|false)\s*\}",
            params,
            re.MULTILINE | re.DOTALL,
        )
        if mldsa_runtime_match is None:
            raise AssertionError("Missing ML_DSA_65_RUNTIME_ENABLED constant in code_quantum_params.h")
        mldsa_runtime_enabled = mldsa_runtime_match.group(1) == "true"

        if re.search(
            r"MODE_V1_ACTIVE_ALGORITHMS\{\s*ALGORITHM_V1_WRAPPED_ECDSA_DER\s*,\s*ALGORITHM_V1_SHA3_256T\s*,\s*\};",
            params,
            re.MULTILINE | re.DOTALL,
        ) is None:
            raise AssertionError("Active algorithm registry declaration drift detected in code_quantum_params.h")

        assert_equal(info["enabled"], True)
        assert_equal(info["mode_wrapped_ecdsa"], mode_wrapped_ecdsa)

        assert_equal(info["algorithms"]["wrapped_ecdsa_der"], algorithm_wrapped_ecdsa_der)
        assert_equal(info["algorithms"]["sha3_256t"], algorithm_sha3_256t)
        assert_equal(info["algorithms"]["mldsa_65"], algorithm_mldsa_65)

        assert_equal(info["active_algorithms"], [algorithm_wrapped_ecdsa_der, algorithm_sha3_256t])
        assert_equal(info["capabilities"]["mldsa_65_runtime_enabled"], mldsa_runtime_enabled)
        assert_equal(
            info["capabilities"]["mldsa_65_verify_state"],
            "available" if info["capabilities"]["mldsa_65_native_verify_available"] else "unavailable",
        )
        assert_equal(info["capabilities"]["mldsa_65_native_signing_available"], False)
        assert_equal(info["capabilities"]["code_quantum_signing_disabled"], True)
        assert_equal(info["capabilities"]["code_quantum_signing_verify_only"], False)
        assert_equal(info["capabilities"]["code_quantum_signing_enabled"], False)
        assert_equal(info["capabilities"]["code_quantum_signing_state"], "disabled")
        assert_equal(info["capabilities"]["external_backend_scaffold_enabled"], False)
        assert_equal(info["capabilities"]["external_backend_header_detected"], False)
        assert_equal(info["capabilities"]["external_backend_verify_api_declared"], False)
        assert_equal(info["capabilities"]["external_backend_verify_linked"], False)
        assert_equal(info["capabilities"]["external_backend_bridge_ready"], False)

        # Regression: toggling wallet signing gate must move signing state from
        # disabled to verify_only when native signer remains unavailable.
        self.restart_node(0, extra_args=["-enablecodequantumsigning=1"])
        info_enabled_gate = self.nodes[0].getcodequantuminfo()
        assert_equal(
            info_enabled_gate["capabilities"]["mldsa_65_verify_state"],
            "available" if info_enabled_gate["capabilities"]["mldsa_65_native_verify_available"] else "unavailable",
        )
        assert_equal(info_enabled_gate["capabilities"]["mldsa_65_native_signing_available"], False)
        assert_equal(info_enabled_gate["capabilities"]["code_quantum_signing_disabled"], False)
        assert_equal(info_enabled_gate["capabilities"]["code_quantum_signing_verify_only"], True)
        assert_equal(info_enabled_gate["capabilities"]["code_quantum_signing_enabled"], False)
        assert_equal(info_enabled_gate["capabilities"]["code_quantum_signing_state"], "verify_only")

        assert_equal(info["limits"]["max_wrapped_sig_size"], max_wrapped_sig_size)
        assert_equal(info["limits"]["max_envelope_size"], max_envelope_size)

        assert_equal(info["policy"]["default_consensus_block_size"], 32000000)
        assert_equal(info["policy"]["pow_target_spacing"], 600)
        assert_equal(info["policy"]["pow_target_spacing_sha3"], 60)
        assert_equal(info["policy"]["sha3_version_bit"], 4096)

        chain = info["policy"]["chain"]
        assert_equal(chain, self.chain)

        genesis = info["policy"]["genesis"]
        expected_genesis_keys = ["hash", "merkle_root", "time", "nonce", "bits", "version", "reward_sats"]
        assert_equal(sorted(genesis.keys()), sorted(expected_genesis_keys))
        assert_equal(genesis["reward_sats"], 5000000000)

        if chain == "regtest":
            assert_equal(genesis["hash"], "00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac")
            assert_equal(genesis["merkle_root"], "d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28")
            assert_equal(genesis["time"], 1773000358)
            assert_equal(genesis["nonce"], 19815)
            assert_equal(genesis["bits"], 486604799)
            assert_equal(genesis["version"], 1)
        elif chain == "testnet4":
            assert_equal(genesis["hash"], "00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac")
            assert_equal(genesis["merkle_root"], "d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28")
            assert_equal(genesis["time"], 1773000358)
            assert_equal(genesis["nonce"], 19815)
            assert_equal(genesis["bits"], 486604799)
            assert_equal(genesis["version"], 1)
        else:
            assert_equal(genesis["hash"], "00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac")
            assert_equal(genesis["merkle_root"], "d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28")
            assert_equal(genesis["time"], 1773000358)
            assert_equal(genesis["nonce"], 19815)
            assert_equal(genesis["bits"], 486604799)
            assert_equal(genesis["version"], 1)

        if chain == "regtest":
            if info["policy"]["sha3_height"] not in (1, 2016):
                raise AssertionError(
                    f"Unexpected regtest sha3_height: {info['policy']['sha3_height']} (expected 1 or 2016)"
                )
        else:
            assert_equal(info["policy"]["sha3_height"], 21000)

        if chain == "main":
            assert_equal(info["policy"]["hard_fork_height"], 108500)
            assert_equal(info["policy"]["checkpoint_height"], 108300)
        elif chain == "regtest":
            assert_equal(info["policy"]["hard_fork_height"], 0)
            assert_equal(info["policy"]["checkpoint_height"], 0)
        else:
            assert_equal(info["policy"]["hard_fork_height"], 2147483647)
            assert_equal(info["policy"]["checkpoint_height"], 2147483647)

        activation_matrix = info["policy"]["activation_matrix"]
        expected_activation_keys = [
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
        ]
        assert_equal(sorted(activation_matrix.keys()), sorted(expected_activation_keys))
        always_active_keys = [
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
        ]
        for key in always_active_keys:
            assert_equal(activation_matrix[key], -1)
        assert_equal(activation_matrix["upgrade12"], 2147483647)

        if chain == "regtest":
            assert_equal(info["policy"]["segwit_height"], 0)
            assert_equal(info["policy"]["segwit_disabled"], False)
            assert_equal(info["policy"]["taproot_disabled"], False)
        else:
            assert_equal(info["policy"]["segwit_height"], 2147483647)
            assert_equal(info["policy"]["segwit_disabled"], True)
            assert_equal(info["policy"]["taproot_disabled"], True)


if __name__ == '__main__':
    RpcCodeQuantumInfoTest(__file__).main()
