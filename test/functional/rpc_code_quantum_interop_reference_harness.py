#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Code Quantum interoperability vectors against Python reference harness.

This test is mining-free and node-free. It validates deterministic Code Quantum
vector behavior against the independent Python secp256k1 reference verifier used
in the functional test framework.
"""

import hashlib

from test_framework.key import ECKey, ECPubKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


CODE_QUANTUM_VERSION = 1
CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA = 0
CODE_QUANTUM_ALGORITHM_V1_WRAPPED_ECDSA_DER = 0
CODE_QUANTUM_ALGORITHM_V1_SHA3_256T = 1
CODE_QUANTUM_ALGORITHM_V1_ML_DSA_65 = 2
SIGHASH_ALL = 1


def hash_sha3_256t(input32: bytes) -> bytes:
    out = input32
    out = hashlib.sha3_256(out).digest()
    out = hashlib.sha3_256(out).digest()
    out = hashlib.sha3_256(out).digest()
    return out


def make_envelope(*, mode: int, algorithm: int, wrapped_sig: bytes) -> bytes:
    return b"CQ" + bytes([
        CODE_QUANTUM_VERSION,
        mode,
        algorithm,
        len(wrapped_sig),
    ]) + wrapped_sig


def decode_envelope(envelope: bytes):
    if len(envelope) < 6:
        raise ValueError("envelope too short")
    if envelope[0:2] != b"CQ":
        raise ValueError("missing CQ marker")
    version = envelope[2]
    mode = envelope[3]
    algorithm = envelope[4]
    wrapped_len = envelope[5]
    payload = envelope[6:]
    if len(payload) != wrapped_len:
        raise ValueError("non-canonical wrapped signature length")
    return version, mode, algorithm, payload


class RpcCodeQuantumInteropReferenceHarnessTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def run_test(self):
        self.log.info("Build deterministic reference key pair")
        privkey = ECKey()
        privkey.set((1).to_bytes(32, "big"), True)
        pubkey_bytes = privkey.get_pubkey().get_bytes()
        pubkey = ECPubKey()
        pubkey.set(pubkey_bytes)

        # Use fixed message bytes so the vectors are deterministic across runs.
        msg_legacy = hashlib.sha256(b"cq-interop-legacy").digest()
        msg_sha3 = hash_sha3_256t(msg_legacy)

        self.log.info("Construct wrapped signatures for legacy and SHA3-256t vectors")
        der_legacy = privkey.sign_ecdsa(msg_legacy, rfc6979=True)
        der_sha3 = privkey.sign_ecdsa(msg_sha3, rfc6979=True)
        wrapped_legacy = der_legacy + bytes([SIGHASH_ALL])
        wrapped_sha3 = der_sha3 + bytes([SIGHASH_ALL])

        env_legacy = make_envelope(
            mode=CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA,
            algorithm=CODE_QUANTUM_ALGORITHM_V1_WRAPPED_ECDSA_DER,
            wrapped_sig=wrapped_legacy,
        )
        env_sha3 = make_envelope(
            mode=CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA,
            algorithm=CODE_QUANTUM_ALGORITHM_V1_SHA3_256T,
            wrapped_sig=wrapped_sha3,
        )
        env_mldsa = make_envelope(
            mode=CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA,
            algorithm=CODE_QUANTUM_ALGORITHM_V1_ML_DSA_65,
            wrapped_sig=wrapped_legacy,
        )

        self.log.info("Validate envelope metadata and canonical length behavior")
        v, m, a, p = decode_envelope(env_legacy)
        assert_equal(v, CODE_QUANTUM_VERSION)
        assert_equal(m, CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA)
        assert_equal(a, CODE_QUANTUM_ALGORITHM_V1_WRAPPED_ECDSA_DER)
        assert_equal(p, wrapped_legacy)

        v, m, a, p = decode_envelope(env_sha3)
        assert_equal(v, CODE_QUANTUM_VERSION)
        assert_equal(m, CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA)
        assert_equal(a, CODE_QUANTUM_ALGORITHM_V1_SHA3_256T)
        assert_equal(p, wrapped_sha3)

        v, m, a, p = decode_envelope(env_mldsa)
        assert_equal(v, CODE_QUANTUM_VERSION)
        assert_equal(m, CODE_QUANTUM_MODE_V1_WRAPPED_ECDSA)
        assert_equal(a, CODE_QUANTUM_ALGORITHM_V1_ML_DSA_65)
        assert_equal(p, wrapped_legacy)

        malformed = bytearray(env_legacy)
        malformed[-1] ^= 0x01
        malformed[5] = malformed[5] + 1
        try:
            decode_envelope(bytes(malformed))
            raise AssertionError("malformed envelope unexpectedly decoded")
        except ValueError:
            pass

        self.log.info("Validate interoperability vectors with independent Python secp256k1 verifier")
        assert pubkey.verify_ecdsa(der_legacy, msg_legacy, low_s=True)
        assert pubkey.verify_ecdsa(der_sha3, msg_sha3, low_s=True)

        # Digest-path mismatch vectors must fail deterministically.
        assert not pubkey.verify_ecdsa(der_legacy, msg_sha3, low_s=True)
        assert not pubkey.verify_ecdsa(der_sha3, msg_legacy, low_s=True)

        tampered_der = bytearray(der_sha3)
        tampered_der[-1] ^= 0x01
        assert not pubkey.verify_ecdsa(bytes(tampered_der), msg_sha3, low_s=True)


if __name__ == "__main__":
    RpcCodeQuantumInteropReferenceHarnessTest(__file__).main()
