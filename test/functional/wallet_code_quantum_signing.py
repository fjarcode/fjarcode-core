#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Exercise Code Quantum wallet signing gate for SCRIPTHASH32 spends."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal


class WalletCodeQuantumSigningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _build_quantum_spend_hex(self, wallet, quantum_addr):
        utxos = wallet.listunspent(1, 9999999, [quantum_addr])
        assert_greater_than_or_equal(len(utxos), 1)
        utxo = utxos[0]

        destination = wallet.getnewaddress("", "legacy")
        send_value = Decimal(utxo["amount"]) - Decimal("0.001")
        assert send_value > 0

        raw = wallet.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: send_value}],
        )
        return raw

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="cqwallet", descriptors=True, load_on_startup=True)
        wallet = self.nodes[0].get_wallet_rpc("cqwallet")

        mining_addr = wallet.getnewaddress("", "legacy")
        self.generatetoaddress(self.nodes[0], 110, mining_addr)

        quantum_addr = wallet.getnewquantumaddress("cq-sign-gate")
        wallet.sendtoaddress(quantum_addr, Decimal("1.0"))
        self.generatetoaddress(self.nodes[0], 1, mining_addr)

        self.restart_node(0, extra_args=["-enablecodequantumsigning=0"])
        wallet = self.nodes[0].get_wallet_rpc("cqwallet")

        raw_disabled = self._build_quantum_spend_hex(wallet, quantum_addr)
        sign_disabled = wallet.signrawtransactionwithwallet(raw_disabled)
        assert_equal(sign_disabled["complete"], False)
        assert "errors" in sign_disabled
        assert any("Code Quantum input signing is disabled" in err["error"] for err in sign_disabled["errors"])

        self.restart_node(0, extra_args=["-enablecodequantumsigning=1"])
        wallet = self.nodes[0].get_wallet_rpc("cqwallet")

        raw_enabled = self._build_quantum_spend_hex(wallet, quantum_addr)
        sign_enabled = wallet.signrawtransactionwithwallet(raw_enabled)
        assert_equal(sign_enabled["complete"], True)
        assert "errors" not in sign_enabled


if __name__ == "__main__":
    WalletCodeQuantumSigningTest(__file__).main()
