#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze getcodequantumaddress RPC help contract."""

from test_framework.test_framework import BitcoinTestFramework


class RpcCodeQuantumHelpContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        help_index = self.nodes[0].help()
        assert "getcodequantumaddress" in help_index

        help_text = self.nodes[0].help("getcodequantumaddress")

        required_fragments = [
            "getcodequantumaddress",
            "Build a Code Quantum cashaddr destination from a 32-byte hash.",
            '"hash"',
            "32-byte hex hash for Code Quantum address payload",
            '"address"',
            '"scriptPubKey"',
            '"isquantum"',
            '"quantum_type"',
            '"quantum_hash"',
            "Examples:",
        ]

        for fragment in required_fragments:
            assert fragment in help_text, f"Missing help fragment: {fragment}"


if __name__ == "__main__":
    RpcCodeQuantumHelpContractTest(__file__).main()
