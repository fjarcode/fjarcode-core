#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Test getnewquantumaddress wallet RPC contract."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RpcGetNewQuantumAddressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="cqwallet", load_on_startup=True)
        wallet = self.nodes[0].get_wallet_rpc("cqwallet")

        addr = wallet.getnewquantumaddress()
        assert addr.startswith("fjarcoderegtest:"), "expected regtest quantum cashaddr prefix"

        # A freshly generated quantum address must be owned and solvable by the wallet.
        addr_info = wallet.getaddressinfo(addr)
        assert_equal(addr_info["isquantum"], True)
        assert_equal(addr_info["ismine"], True)
        assert_equal(addr_info["solvable"], True)

        info = self.nodes[0].validateaddress(addr)
        assert_equal(info["isvalid"], True)
        assert_equal(info["isquantum"], True)
        assert_equal(info["quantum_type"], "code_quantum_cashaddr")

        expected_script = "aa20" + info["quantum_hash"] + "87"
        assert_equal(info["scriptPubKey"], expected_script)

        labeled_addr = wallet.getnewquantumaddress("cq-wallet-label")
        labeled_info = wallet.getaddressinfo(labeled_addr)
        assert_equal(labeled_info["labels"], ["cq-wallet-label"])

        selector_addr = wallet.getnewaddress("", "quantum")
        selector_info = self.nodes[0].validateaddress(selector_addr)
        assert_equal(selector_info["isvalid"], True)
        assert_equal(selector_info["isquantum"], True)
        assert_equal(selector_info["quantum_type"], "code_quantum_cashaddr")

        default_addr = wallet.getnewaddress()
        default_info = self.nodes[0].validateaddress(default_addr)
        assert_equal(default_info["isvalid"], True)
        assert_equal(default_info["isquantum"], True)
        assert_equal(default_info["quantum_type"], "code_quantum_cashaddr")

        default_wallet_info = wallet.getaddressinfo(default_addr)
        assert_equal(default_wallet_info["ismine"], True)
        assert_equal(default_wallet_info["solvable"], True)

        # Regression check: after restart, previously issued quantum addresses
        # must remain wallet-owned and solvable.
        self.restart_node(0)
        wallet = self.nodes[0].get_wallet_rpc("cqwallet")
        after_restart_info = wallet.getaddressinfo(addr)
        assert_equal(after_restart_info["isquantum"], True)
        assert_equal(after_restart_info["ismine"], True)
        assert_equal(after_restart_info["solvable"], True)

        default_labeled_addr = wallet.getnewaddress("cq-default-label")
        default_labeled_info = wallet.getaddressinfo(default_labeled_addr)
        assert_equal(default_labeled_info["labels"], ["cq-default-label"])

        selector_labeled_addr = wallet.getnewaddress("cq-selector-label", "quantum")
        selector_labeled_info = wallet.getaddressinfo(selector_labeled_addr)
        assert_equal(selector_labeled_info["labels"], ["cq-selector-label"])


if __name__ == "__main__":
    RpcGetNewQuantumAddressTest(__file__).main()
