#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze getcodequantumaddress JSON schema contract (keys + value types)."""

from test_framework.cq_schema import assert_exact_keys, assert_type
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class RpcCodeQuantumAddressSchemaContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        quantum_hash = "22" * 32
        info = self.nodes[0].getcodequantumaddress(quantum_hash)

        assert_exact_keys(
            info,
            ["address", "scriptPubKey", "isquantum", "quantum_type", "quantum_hash"],
            "root",
        )
        assert_type(info["address"], str, "root.address")
        assert_type(info["scriptPubKey"], str, "root.scriptPubKey")
        assert_type(info["isquantum"], bool, "root.isquantum")
        assert_type(info["quantum_type"], str, "root.quantum_type")
        assert_type(info["quantum_hash"], str, "root.quantum_hash")

        assert info["address"].startswith("fjarcoderegtest:"), "address: expected regtest cashaddr prefix"
        assert_equal(info["isquantum"], True)
        assert_equal(info["quantum_type"], "code_quantum_cashaddr")
        assert_equal(info["quantum_hash"], quantum_hash)

        expected_script_pub_key = "aa20" + quantum_hash + "87"
        assert_equal(info["scriptPubKey"], expected_script_pub_key)

        assert_raises_rpc_error(
            -8,
            "hash must be exactly 32 bytes",
            self.nodes[0].getcodequantumaddress,
            "22" * 31,
        )


if __name__ == "__main__":
    RpcCodeQuantumAddressSchemaContractTest(__file__).main()
