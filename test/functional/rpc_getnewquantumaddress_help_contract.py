#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze getnewquantumaddress help contract."""

from test_framework.test_framework import BitcoinTestFramework


class RpcGetNewQuantumAddressHelpContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="cqwallet")
        wallet = self.nodes[0].get_wallet_rpc("cqwallet")

        help_index = wallet.help()
        assert "getnewquantumaddress" in help_index

        help_text = wallet.help("getnewquantumaddress")

        required_fragments = [
            "getnewquantumaddress",
            "Returns a new Code Quantum cashaddr for receiving payments.",
            '"label"',
            "added to the address book",
            "The new Code Quantum cashaddr",
            "Examples:",
        ]

        for fragment in required_fragments:
            assert fragment in help_text, f"Missing help fragment: {fragment}"


if __name__ == "__main__":
    RpcGetNewQuantumAddressHelpContractTest(__file__).main()
