#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Regtest deterministic activation harness for Code Quantum policy replay.

This test keeps execution mining-free and validates that regtest can be
restarted with deterministic buried-deployment activation overrides while
Code Quantum policy anchors remain stable.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RpcCodeQuantumRegtestActivationHarnessTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "regtest"
        self.setup_clean_chain = True

    def assert_regtest_cq_policy_stable(self, info):
        policy = info["policy"]
        activation = policy["activation_matrix"]

        assert_equal(policy["chain"], "regtest")
        assert_equal(policy["hard_fork_height"], 0)
        assert_equal(policy["checkpoint_height"], 0)
        assert_equal(policy["sha3_height"], 2016)
        assert_equal(policy["pow_target_spacing"], 600)
        assert_equal(policy["pow_target_spacing_sha3"], 60)
        assert_equal(policy["sha3_version_bit"], 4096)

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
            assert_equal(activation[key], -1)
        assert_equal(activation["upgrade12"], 2147483647)

    def run_test(self):
        self.log.info("Check baseline regtest Code Quantum activation policy")
        baseline = self.nodes[0].getcodequantuminfo()
        self.assert_regtest_cq_policy_stable(baseline)
        assert_equal(baseline["policy"]["segwit_height"], 0)

        self.log.info("Restart with deterministic buried activation overrides for mainnet-style rehearsal")
        buried_rehearsal_args = [
            "-testactivationheight=bip34@150000",
            "-testactivationheight=dersig@150000",
            "-testactivationheight=cltv@150000",
            "-testactivationheight=csv@150000",
            "-testactivationheight=segwit@150000",
        ]
        self.restart_node(0, extra_args=buried_rehearsal_args)

        overridden = self.nodes[0].getcodequantuminfo()
        self.assert_regtest_cq_policy_stable(overridden)
        assert_equal(overridden["policy"]["segwit_height"], 150000)

        self.log.info("Restart back to default args and confirm deterministic baseline restoration")
        self.stop_node(0)
        self.start_node(0)

        restored = self.nodes[0].getcodequantuminfo()
        self.assert_regtest_cq_policy_stable(restored)
        assert_equal(restored["policy"]["segwit_height"], 0)


if __name__ == "__main__":
    RpcCodeQuantumRegtestActivationHarnessTest(__file__).main()
