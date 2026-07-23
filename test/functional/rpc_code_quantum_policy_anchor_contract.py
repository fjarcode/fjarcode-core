#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze getcodequantuminfo policy-anchor runtime contract."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RpcCodeQuantumPolicyAnchorContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        info = self.nodes[0].getcodequantuminfo()
        policy = info["policy"]
        activation = policy["activation_matrix"]

        chain = policy["chain"]
        assert_equal(chain, self.chain)

        if chain == "main":
            assert_equal(policy["hard_fork_height"], 150000)
            assert_equal(policy["checkpoint_height"], 145000)
            assert_equal(policy["hard_fork_height"] - policy["checkpoint_height"], 5000)
        else:
            assert_equal(policy["hard_fork_height"], 2147483647)
            assert_equal(policy["checkpoint_height"], 2147483647)

        # Current FJAR policy keeps upgrade12 explicitly disabled.
        assert "upgrade12" in activation
        assert_equal(activation["upgrade12"], 2147483647)

        # Neighboring upgrade11 remains active, guarding against accidental swaps.
        assert_equal(activation["upgrade11"], -1)


if __name__ == "__main__":
    RpcCodeQuantumPolicyAnchorContractTest(__file__).main()
