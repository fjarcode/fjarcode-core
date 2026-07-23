#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze FJAR address encoding contract.

Guards these migration requirements:
- Legacy Base58 remains accepted (compatibility path).
- PKHash/ScriptHash string encoding defaults to CashAddr prefix.
- Code Quantum ScriptHash32 encodes as CashAddr and validates.
"""

from test_framework.address import byte_to_base58
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RpcAddressEncodingContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        expected_cashaddr_prefix = "fjarcoderegtest"

        # Legacy Base58 compatibility must remain valid for P2PKH destinations.
        hash20 = bytes.fromhex("00112233445566778899aabbccddeeff00112233")
        legacy_base58_addr = byte_to_base58(hash20, 111)
        legacy_base58_info = self.nodes[0].validateaddress(legacy_base58_addr)
        assert_equal(legacy_base58_info["isvalid"], True)

        p2pkh_script_hex = "76a914" + hash20.hex() + "88ac"
        decoded_p2pkh = self.nodes[0].decodescript(p2pkh_script_hex)
        p2pkh_cashaddr = decoded_p2pkh["address"]
        assert p2pkh_cashaddr.startswith(expected_cashaddr_prefix + ":")
        assert_equal(self.nodes[0].validateaddress(p2pkh_cashaddr)["isvalid"], True)
        assert_equal(legacy_base58_info["scriptPubKey"], p2pkh_script_hex)

        # Code Quantum address path (OP_HASH256 <32-byte hash> OP_EQUAL) must
        # encode as CashAddr and remain a valid destination.
        hash32_hex = "11" * 32
        quantum_script_hex = "aa20" + hash32_hex + "87"
        decoded_quantum = self.nodes[0].decodescript(quantum_script_hex)
        quantum_addr = decoded_quantum["address"]
        assert quantum_addr.startswith(expected_cashaddr_prefix + ":")

        quantum_info = self.nodes[0].validateaddress(quantum_addr)
        assert_equal(quantum_info["isvalid"], True)
        assert_equal(quantum_info["scriptPubKey"], quantum_script_hex)
        assert_equal(quantum_info["isscript"], True)

        self.log.info("Address encoding contract checks passed")


if __name__ == "__main__":
    RpcAddressEncodingContractTest(__file__).main()
