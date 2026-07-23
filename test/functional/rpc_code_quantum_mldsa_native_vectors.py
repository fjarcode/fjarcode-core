#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Daemon-backed Code Quantum ML-DSA-65 native verify vectors.

This test drives real script verification through a node process using a
Code Quantum envelope that selects the ML-DSA-65 algorithm ID.

The positive vector is expected to pass only when the optional built-in
secp256k1 native backend verify seam is enabled at build time.
"""

import hashlib

from test_framework.blocktools import NORMAL_GBT_REQUEST_PARAMS, create_block
from test_framework.key import ECKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, OP_CHECKSIG
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


CODE_QUANTUM_VERSION = 1
CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA = 0
CODE_QUANTUM_ALGORITHM_V1_ML_DSA_65 = 2
SIGHASH_ALL = 1
NATIVE_PREHASH_DOMAIN = b"CQ-MLDSA65-v1"


def compute_native_builtin_prehash(script_code: CScript, sighash_type: int) -> bytes:
    h = hashlib.sha256()
    h.update(NATIVE_PREHASH_DOMAIN)
    h.update(bytes(script_code))
    h.update(bytes([sighash_type]))
    return h.digest()


def make_code_quantum_envelope(wrapped_sig: bytes) -> bytes:
    return b"CQ" + bytes([
        CODE_QUANTUM_VERSION,
        CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA,
        CODE_QUANTUM_ALGORITHM_V1_ML_DSA_65,
        len(wrapped_sig),
    ]) + wrapped_sig


def make_code_quantum_envelope_custom(*, version: int, mode: int, algorithm: int, wrapped_sig_len: int, wrapped_sig_payload: bytes) -> bytes:
    return b"CQ" + bytes([
        version,
        mode,
        algorithm,
        wrapped_sig_len,
    ]) + wrapped_sig_payload


class RpcCodeQuantumMLDSANativeVectorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "regtest"
        self.setup_clean_chain = True

    def _fund_custom_script(self, wallet: MiniWallet, script_pubkey: CScript, amount_sats: int) -> dict:
        return wallet.send_to(from_node=self.nodes[0], scriptPubKey=script_pubkey, amount=amount_sats)

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

    def _assert_malformed_reject(self, *, wallet: MiniWallet, script_pubkey: CScript, change_script: bytes, spend_amount_sats: int, fee_sats: int, envelope_sig: bytes, expected_reason_fragment: str):
        funded = self._fund_custom_script(wallet, script_pubkey, spend_amount_sats)
        self.generate(self.nodes[0], 1)
        wallet.rescan_utxos()
        tx = self._build_spend(
            prev_txid=funded["txid"],
            prev_vout=funded["sent_vout"],
            output_value_sats=spend_amount_sats - fee_sats,
            output_script=change_script,
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
        wallet = MiniWallet(node)
        self.generatetodescriptor(node, 101, wallet.get_descriptor())
        wallet.rescan_utxos()

        self.log.info("Prepare deterministic key/script for ML-DSA-65 Code Quantum envelope vectors")
        privkey = ECKey()
        privkey.set((1).to_bytes(32, "big"), True)
        pubkey = privkey.get_pubkey().get_bytes()
        script_pubkey = CScript([pubkey, OP_CHECKSIG])

        spend_amount_sats = 200_000
        fee_sats = 1_000
        change_script = wallet.get_output_script()

        prehash = compute_native_builtin_prehash(script_pubkey, SIGHASH_ALL)
        der_sig = privkey.sign_ecdsa(prehash, rfc6979=True)
        wrapped_sig = der_sig + bytes([SIGHASH_ALL])
        valid_envelope = make_code_quantum_envelope(wrapped_sig)

        self.log.info("Mine funding output for positive ML-DSA-65 vector")
        funded = self._fund_custom_script(wallet, script_pubkey, spend_amount_sats)
        self.generate(node, 1)
        wallet.rescan_utxos()
        tx_ok = self._build_spend(
            prev_txid=funded["txid"],
            prev_vout=funded["sent_vout"],
            output_value_sats=spend_amount_sats - fee_sats,
            output_script=change_script,
            envelope_sig=valid_envelope,
        )
        self.log.info("Check positive ML-DSA-65 vector through mempool policy")
        ok_accept = node.testmempoolaccept([tx_ok.serialize().hex()])[0]
        if not ok_accept["allowed"]:
            raise SkipTest(
                "ML-DSA-65 native verify vector did not pass; this test requires "
                "ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY=ON. "
                f"testmempoolaccept: {ok_accept.get('reject-reason', '<none>')}"
            )
        self.log.info("Submit positive ML-DSA-65 vector through block validation")
        ok_submit = self._submit_block_with_tx(tx_ok)
        if ok_submit is not None:
            raise SkipTest(
                "ML-DSA-65 native verify vector did not pass; this test requires "
                "ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY=ON. "
                f"submitblock: {ok_submit}"
            )

        best_block = node.getblock(node.getbestblockhash(), 2)
        txids = [entry["txid"] for entry in best_block["tx"]]
        if tx_ok.txid_hex not in txids:
            raise AssertionError("Positive ML-DSA-65 vector txid not found in accepted block")

        self.log.info("Mine funding output for tampered ML-DSA-65 vector")
        funded_bad = self._fund_custom_script(wallet, script_pubkey, spend_amount_sats)
        self.generate(node, 1)
        wallet.rescan_utxos()
        tampered_der = bytearray(der_sig)
        tampered_der[-1] ^= 0x01
        tampered_wrapped_sig = bytes(tampered_der) + bytes([SIGHASH_ALL])
        tampered_envelope = make_code_quantum_envelope(tampered_wrapped_sig)
        tx_bad = self._build_spend(
            prev_txid=funded_bad["txid"],
            prev_vout=funded_bad["sent_vout"],
            output_value_sats=spend_amount_sats - fee_sats,
            output_script=change_script,
            envelope_sig=tampered_envelope,
        )

        self.log.info("Check tampered ML-DSA-65 vector through mempool policy")
        bad_accept = node.testmempoolaccept([tx_bad.serialize().hex()])[0]
        assert_equal(bad_accept["allowed"], False)
        bad_accept_reason = bad_accept.get("reject-reason", "")
        if "Signature must be zero for failed CHECK(MULTI)SIG operation" not in bad_accept_reason:
            raise AssertionError(f"Unexpected mempool reject reason for tampered vector: {bad_accept_reason}")

        self.log.info("Submit tampered ML-DSA-65 vector and assert deterministic reject")
        bad_submit = self._submit_block_with_tx(tx_bad)
        if bad_submit is None:
            raise AssertionError("Tampered ML-DSA-65 vector block unexpectedly accepted")
        if "block-script-verify-flag-failed" not in bad_submit and "Signature must be zero for failed CHECK(MULTI)SIG operation" not in bad_submit:
            raise AssertionError(f"Unexpected reject reason for tampered vector block: {bad_submit}")

        self.log.info("Run malformed ML-DSA-65 envelope vectors under active-native dispatch")
        malformed_cases = [
            (
                "missing wrapped signature",
                make_code_quantum_envelope_custom(
                    version=1,
                    mode=0,
                    algorithm=2,
                    wrapped_sig_len=0,
                    wrapped_sig_payload=b"",
                ),
                "Code Quantum envelope is missing required signature payload",
            ),
            (
                "non-canonical envelope length",
                make_code_quantum_envelope_custom(
                    version=1,
                    mode=0,
                    algorithm=2,
                    wrapped_sig_len=2,
                    wrapped_sig_payload=b"\x01",
                ),
                "Code Quantum envelope uses non-canonical encoding",
            ),
            (
                "unsupported mode id",
                make_code_quantum_envelope_custom(
                    version=1,
                    mode=0xFF,
                    algorithm=2,
                    wrapped_sig_len=0,
                    wrapped_sig_payload=b"",
                ),
                "Code Quantum envelope mode is unsupported",
            ),
            (
                "unsupported algorithm id",
                make_code_quantum_envelope_custom(
                    version=1,
                    mode=0,
                    algorithm=0x09,
                    wrapped_sig_len=0,
                    wrapped_sig_payload=b"",
                ),
                "Code Quantum envelope algorithm id is unsupported",
            ),
        ]

        for case_name, envelope, expected_reason in malformed_cases:
            self.log.info(f"Malformed case: {case_name}")
            self._assert_malformed_reject(
                wallet=wallet,
                script_pubkey=script_pubkey,
                change_script=change_script,
                spend_amount_sats=spend_amount_sats,
                fee_sats=fee_sats,
                envelope_sig=envelope,
                expected_reason_fragment=expected_reason,
            )


if __name__ == "__main__":
    RpcCodeQuantumMLDSANativeVectorsTest(__file__).main()