#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Test getcodequantumaddress RPC output contract."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class RpcCodeQuantumAddressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        quantum_hash = "11" * 32
        expected_script = "aa20" + quantum_hash + "87"

        info = self.nodes[0].getcodequantumaddress(quantum_hash)

        assert info["address"].startswith("fjarcoderegtest:")
        assert_equal(info["scriptPubKey"], expected_script)
        assert_equal(info["isquantum"], True)
        assert_equal(info["quantum_type"], "code_quantum_cashaddr")
        assert_equal(info["quantum_hash"], quantum_hash)

        validated = self.nodes[0].validateaddress(info["address"])
        assert_equal(validated["isvalid"], True)
        assert_equal(validated["scriptPubKey"], expected_script)
        assert_equal(validated["isquantum"], True)
        assert_equal(validated["quantum_type"], "code_quantum_cashaddr")
        assert_equal(validated["quantum_hash"], quantum_hash)

        assert_raises_rpc_error(
            -8,
            "hash must be exactly 32 bytes",
            self.nodes[0].getcodequantumaddress,
            "11" * 31,
        )


if __name__ == "__main__":
    RpcCodeQuantumAddressTest(__file__).main()
