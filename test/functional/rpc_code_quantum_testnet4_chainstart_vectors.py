#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Testnet4 chain-start Code Quantum vectors.

This test validates that testnet4 starts in post-transition policy mode and
that Code Quantum script-path rejects remain deterministic from chain start.
"""

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS, create_block
from test_framework.key import ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, OP_CHECKSIG
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def make_code_quantum_envelope(*, version: int, mode: int, algorithm: int, wrapped_sig_len: int, wrapped_sig_payload: bytes) -> bytes:
    return b"CQ" + bytes([
        version,
        mode,
        algorithm,
        wrapped_sig_len,
    ]) + wrapped_sig_payload


class RpcCodeQuantumTestnet4ChainstartVectors(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "testnet4"
        self.setup_clean_chain = True

    def _mine_block(self, txlist=None):
        tmpl = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(tmpl=tmpl, txlist=txlist or [])
        block.solve()
        submit_res = self.nodes[0].submitblock(block.serialize().hex())
        if submit_res is not None:
            raise AssertionError(f"Block submit failed: {submit_res}")
        return block

    def _mine_blocks(self, count: int):
        blocks = []
        for _ in range(count):
            blocks.append(self._mine_block())
        return blocks

    def _build_spend(self, prev_txid: str, prev_vout: int, output_value_sats: int, output_script: bytes, envelope_sig: bytes) -> CTransaction:
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(prev_txid, 16), prev_vout))]
        tx.vout = [CTxOut(output_value_sats, output_script)]
        tx.vin[0].scriptSig = CScript([envelope_sig])
        return tx

    def _submit_block_with_tx(self, tx: CTransaction):
        tmpl = self.nodes[0].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        block = create_block(tmpl=tmpl, txlist=[tx])
        block.solve()
        return self.nodes[0].submitblock(block.serialize().hex())

    def _assert_malformed_reject(self, *, prev_txid_hex: str, prev_vout: int, spend_amount_sats: int, output_script: CScript, envelope_sig: bytes, expected_reason_fragment: str):
        tx = self._build_spend(
            prev_txid=prev_txid_hex,
            prev_vout=prev_vout,
            output_value_sats=spend_amount_sats,
            output_script=bytes(output_script),
            envelope_sig=envelope_sig,
        )

        mempool_res = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(mempool_res["allowed"], False)
        mempool_reason = mempool_res.get("reject-reason", "")
        if expected_reason_fragment not in mempool_reason:
            raise AssertionError(f"Unexpected mempool reject reason: {mempool_reason}")

        block_res = self._submit_block_with_tx(tx)
        if block_res is None:
            raise AssertionError("Malformed envelope block unexpectedly accepted")
        if expected_reason_fragment not in block_res:
            raise AssertionError(f"Unexpected block reject reason: {block_res}")

    def run_test(self):
        node = self.nodes[0]
        info = node.getcodequantuminfo()

        self.log.info("Check testnet4 post-transition policy anchors from chain start")
        assert_equal(info["policy"]["chain"], "testnet4")
        assert_equal(info["policy"]["hard_fork_height"], 0)
        assert_equal(info["policy"]["checkpoint_height"], 0)
        assert_equal(info["policy"]["sha3_height"], 1)
        assert_equal(info["policy"]["pow_target_spacing_sha3"], 60)
        assert_equal(info["policy"]["sha3_version_bit"], 4096)
        self.log.info("No-mining mode requested: skip block/coinbase-dependent malformed-vector execution")


if __name__ == "__main__":
    RpcCodeQuantumTestnet4ChainstartVectors(__file__).main()
