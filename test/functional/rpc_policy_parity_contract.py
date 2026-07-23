#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze FJAR policy parity contract in chainparams.cpp.

This is a no-node functional parity guard that ensures the expected FJAR policy
profile remains stable while migration continues.
"""

from pathlib import Path
import re

from test_framework.test_framework import BitcoinTestFramework


class PolicyParityContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def run_test(self):
        srcdir = Path(self.config["environment"]["SRCDIR"])
        chainparams = srcdir / "src" / "kernel" / "chainparams.cpp"
        validation = srcdir / "src" / "validation.cpp"
        node_rpc = srcdir / "src" / "rpc" / "node.cpp"
        wallet_header = srcdir / "src" / "wallet" / "wallet.h"
        text = chainparams.read_text(encoding="utf8")
        validation_text = validation.read_text(encoding="utf8")
        node_rpc_text = node_rpc.read_text(encoding="utf8")
        wallet_text = wallet_header.read_text(encoding="utf8")

        self.assert_match(
            text,
            r"const char\* pszTimestamp\s*=\s*\"08/Mar/2026 In silence, FJARCODE begins\"\s*;",
            "chainparams: expected FJAR genesis timestamp text anchor",
        )

        non_regtest_blocks = [
            ("CMainParams", "main"),
            ("CTestNetParams", "testnet"),
            ("CTestNet4Params", "testnet4"),
            ("SigNetParams", "signet"),
        ]

        for class_name, chain_label in non_regtest_blocks:
            block = self.extract_class_block(text, class_name)
            self.assert_match(
                block,
                r"consensus\.nDefaultConsensusBlockSize\s*=\s*32000000\s*;",
                f"{chain_label}: expected default consensus block size to remain 32000000",
            )
            self.assert_match(
                block,
                r"consensus\.asertActivationHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected ASERT to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.FJARCODEActivationHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected FJARCODE activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.uahfHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected UAHF activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.daaHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected DAA activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.magneticAnomalyHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected magnetic anomaly activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.gravitonHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected graviton activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.phononHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected phonon activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.axionHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected axion activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.upgrade8Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected upgrade8 activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.upgrade9Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected upgrade9 activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.upgrade10Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected upgrade10 activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.upgrade11Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected upgrade11 activation to remain always active",
            )
            self.assert_match(
                block,
                r"consensus\.upgrade12Height\s*=\s*Consensus::NEVER_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected upgrade12 activation to remain disabled",
            )
            self.assert_match(
                block,
                r"consensus\.nPowTargetSpacing\s*=\s*10\s*\*\s*60\s*;",
                f"{chain_label}: expected pre-SHA3 target spacing to remain 600s",
            )
            self.assert_match(
                block,
                r"consensus\.nPowTargetSpacingSHA3\s*=\s*60\s*;",
                f"{chain_label}: expected post-SHA3 target spacing to remain 60s",
            )
            self.assert_match(
                block,
                r"consensus\.nASERTHalfLife\s*=\s*Consensus::Params::ASERT_HALFLIFE_2_DAYS\s*;",
                f"{chain_label}: expected ASERT half-life to remain 2 days",
            )
            expected_sha3_height_pattern = r"consensus\.SHA3Height\s*=\s*21000\s*;"
            expected_sha3_height_message = f"{chain_label}: expected SHA3 activation height to remain 21000"
            if class_name == "CTestNet4Params":
                expected_sha3_height_pattern = r"consensus\.SHA3Height\s*=\s*1\s*;"
                expected_sha3_height_message = "testnet4: expected SHA3 activation height to remain 1"
            self.assert_match(
                block,
                expected_sha3_height_pattern,
                expected_sha3_height_message,
            )
            self.assert_match(
                block,
                r"consensus\.SHA3VersionBit\s*=\s*1\s*<<\s*12\s*;",
                f"{chain_label}: expected SHA3 version bit to remain 1<<12",
            )

            if class_name == "CMainParams":
                self.assert_match(
                    block,
                    r"consensus\.BIP34Height\s*=\s*1\s*;",
                    "main: expected BIP34 height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.BIP65Height\s*=\s*1\s*;",
                    "main: expected BIP65 height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.BIP66Height\s*=\s*1\s*;",
                    "main: expected BIP66 height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.CSVHeight\s*=\s*1\s*;",
                    "main: expected CSV height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.fjarPolicyHardForkHeight\s*=\s*108500\s*;",
                    "main: expected FJAR hard-fork anchor height to remain 108500",
                )
                self.assert_match(
                    block,
                    r"consensus\.fjarPolicyCheckpointHeight\s*=\s*108300\s*;",
                    "main: expected FJAR checkpoint/finalization anchor height to remain 108300",
                )
                self.assert_match(
                    block,
                    r"genesis\s*=\s*CreateGenesisBlock\(1773000358,\s*19815,\s*0x1d00ffff,\s*1,\s*50\s*\*\s*COIN\)\s*;",
                    "main: expected FJAR genesis creation parameters",
                )
                self.assert_match(
                    block,
                    r"consensus\.hashGenesisBlock\s*==\s*uint256\{\"00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac\"\}",
                    "main: expected FJAR genesis hash",
                )
                self.assert_match(
                    block,
                    r"genesis\.hashMerkleRoot\s*==\s*uint256\{\"d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28\"\}",
                    "main: expected FJAR genesis merkle root",
                )

            if class_name == "CTestNetParams":
                self.assert_match(
                    block,
                    r"consensus\.BIP34Height\s*=\s*1\s*;",
                    "testnet: expected BIP34 height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.BIP65Height\s*=\s*1\s*;",
                    "testnet: expected BIP65 height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.BIP66Height\s*=\s*1\s*;",
                    "testnet: expected BIP66 height to remain 1",
                )
                self.assert_match(
                    block,
                    r"consensus\.CSVHeight\s*=\s*1\s*;",
                    "testnet: expected CSV height to remain 1",
                )
                self.assert_match(
                    block,
                    r"genesis\s*=\s*CreateGenesisBlock\(1773000358,\s*19815,\s*0x1d00ffff,\s*1,\s*50\s*\*\s*COIN\)\s*;",
                    "testnet: expected FJAR genesis creation parameters",
                )
                self.assert_match(
                    block,
                    r"consensus\.hashGenesisBlock\s*==\s*uint256\{\"00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac\"\}",
                    "testnet: expected FJAR genesis hash",
                )
                self.assert_match(
                    block,
                    r"genesis\.hashMerkleRoot\s*==\s*uint256\{\"d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28\"\}",
                    "testnet: expected FJAR genesis merkle root",
                )

            if class_name == "SigNetParams":
                self.assert_match(
                    block,
                    r"genesis\s*=\s*CreateGenesisBlock\(1773000358,\s*19815,\s*0x1d00ffff,\s*1,\s*50\s*\*\s*COIN\)\s*;",
                    "signet: expected FJAR genesis creation parameters",
                )
                self.assert_match(
                    block,
                    r"consensus\.hashGenesisBlock\s*==\s*uint256\{\"00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac\"\}",
                    "signet: expected FJAR genesis hash",
                )
                self.assert_match(
                    block,
                    r"genesis\.hashMerkleRoot\s*==\s*uint256\{\"d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28\"\}",
                    "signet: expected FJAR genesis merkle root",
                )

            if class_name == "CTestNet4Params":
                self.assert_match(
                    block,
                    r"consensus\.fPowNoRetargeting\s*=\s*false\s*;",
                    "testnet4: expected ASERT retargeting to remain enabled",
                )
                self.assert_match(
                    block,
                    r"genesis\s*=\s*CreateGenesisBlock\(testnet4Timestamp,\s*genesisOutputScript,\s*1784691180,\s*1,\s*0x207fffff,\s*1,\s*50\s*\*\s*COIN\)\s*;",
                    "testnet4: expected genesis creation parameters",
                )
                self.assert_match(
                    block,
                    r"consensus\.hashGenesisBlock\s*==\s*uint256\{\"7058eea2aafcbc11cf3def862acdcfb1217b6a50b3790545b5547d061e050b79\"\}",
                    "testnet4: expected genesis hash",
                )
                self.assert_match(
                    block,
                    r"genesis\.hashMerkleRoot\s*==\s*uint256\{\"b9dc3fca61a139b3ada279cc9815d4eb9c3757d66460a9d237f2d9a3b0ee03d2\"\}",
                    "testnet4: expected genesis merkle root",
                )
            self.assert_match(
                block,
                r"consensus\.SegwitHeight\s*=\s*Consensus::NEVER_ACTIVE_HEIGHT\s*;",
                f"{chain_label}: expected SegWit to remain disabled",
            )
            self.assert_match(
                block,
                r"consensus\.vDeployments\[Consensus::DEPLOYMENT_TAPROOT\]\.nStartTime\s*=\s*Consensus::BIP9Deployment::NEVER_ACTIVE\s*;",
                f"{chain_label}: expected Taproot deployment to remain disabled",
            )

        expected_network_profile = {
            "CMainParams": {
                "label": "main",
                "message_start": ("0xb2", "0xc2", "0xb2", "0xc2"),
                "default_port": 28439,
                "cashaddr_prefix": "fjarcode",
                "pubkey_base58_prefix": 0,
            },
            "CTestNetParams": {
                "label": "testnet",
                "message_start": ("0xb2", "0xc2", "0x0b", "0x11"),
                "default_port": 29439,
                "cashaddr_prefix": "fjarcodetest",
                "pubkey_base58_prefix": 111,
            },
            "CTestNet4Params": {
                "label": "testnet4",
                "message_start": ("0x1c", "0x16", "0x3f", "0x28"),
                "default_port": 48333,
                "cashaddr_prefix": "fjarcodetest4",
                "pubkey_base58_prefix": 111,
            },
            "CRegTestParams": {
                "label": "regtest",
                "message_start": ("0xfa", "0xbf", "0xb5", "0xda"),
                "default_port": 31439,
                "cashaddr_prefix": "fjarcoderegtest",
                "pubkey_base58_prefix": 111,
            },
            "SigNetParams": {
                "label": "signet",
                "message_start": None,
                "default_port": 30439,
                "cashaddr_prefix": "fjarcodesignet",
                "pubkey_base58_prefix": 111,
            },
        }

        for class_name, profile in expected_network_profile.items():
            block = self.extract_class_block(text, class_name)
            label = profile["label"]

            self.assert_match(
                block,
                rf"nDefaultPort\s*=\s*{profile['default_port']}\s*;",
                f"{label}: expected nDefaultPort to remain {profile['default_port']}",
            )
            self.assert_match(
                block,
                rf'cashaddr_prefix\s*=\s*"{profile["cashaddr_prefix"]}"\s*;',
                f"{label}: expected cashaddr_prefix to remain \"{profile['cashaddr_prefix']}\"",
            )
            self.assert_match(
                block,
                rf"base58Prefixes\[PUBKEY_ADDRESS\]\s*=\s*std::vector<unsigned char>\(1,{profile['pubkey_base58_prefix']}\)\s*;",
                f"{label}: expected legacy PUBKEY_ADDRESS prefix to remain {profile['pubkey_base58_prefix']}",
            )

            if profile["message_start"] is not None:
                expected = profile["message_start"]
                self.assert_match(
                    block,
                    rf"pchMessageStart\[0\]\s*=\s*{expected[0]}\s*;",
                    f"{label}: expected pchMessageStart[0] to remain {expected[0]}",
                )
                self.assert_match(
                    block,
                    rf"pchMessageStart\[1\]\s*=\s*{expected[1]}\s*;",
                    f"{label}: expected pchMessageStart[1] to remain {expected[1]}",
                )
                self.assert_match(
                    block,
                    rf"pchMessageStart\[2\]\s*=\s*{expected[2]}\s*;",
                    f"{label}: expected pchMessageStart[2] to remain {expected[2]}",
                )
                self.assert_match(
                    block,
                    rf"pchMessageStart\[3\]\s*=\s*{expected[3]}\s*;",
                    f"{label}: expected pchMessageStart[3] to remain {expected[3]}",
                )

        regtest_block = self.extract_class_block(text, "CRegTestParams")
        self.assert_match(
            regtest_block,
            r"consensus\.nDefaultConsensusBlockSize\s*=\s*32000000\s*;",
            "regtest: expected default consensus block size to remain 32000000",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.nPowTargetSpacing\s*=\s*10\s*\*\s*60\s*;",
            "regtest: expected pre-SHA3 target spacing to remain 600s",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.nPowTargetSpacingSHA3\s*=\s*60\s*;",
            "regtest: expected post-SHA3 target spacing to remain 60s",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.nASERTHalfLife\s*=\s*Consensus::Params::ASERT_HALFLIFE_2_DAYS\s*;",
            "regtest: expected ASERT half-life to remain 2 days",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.SHA3Height\s*=\s*1\s*;",
            "regtest: expected SHA3 activation height to remain 1",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.SHA3VersionBit\s*=\s*1\s*<<\s*12\s*;",
            "regtest: expected SHA3 version bit to remain 1<<12",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.FJARCODEActivationHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected FJARCODE activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.uahfHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected UAHF activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.daaHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected DAA activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.magneticAnomalyHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected magnetic anomaly activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.gravitonHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected graviton activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.phononHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected phonon activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.axionHeight\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected axion activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.upgrade8Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected upgrade8 activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.upgrade9Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected upgrade9 activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.upgrade10Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected upgrade10 activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.upgrade11Height\s*=\s*Consensus::ALWAYS_ACTIVE_HEIGHT\s*;",
            "regtest: expected upgrade11 activation to remain always active",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.upgrade12Height\s*=\s*Consensus::NEVER_ACTIVE_HEIGHT\s*;",
            "regtest: expected upgrade12 activation to remain disabled",
        )
        self.assert_match(
            regtest_block,
            r"genesis\s*=\s*CreateGenesisBlock\(1773000358,\s*19815,\s*0x1d00ffff,\s*1,\s*50\s*\*\s*COIN\)\s*;",
            "regtest: expected FJAR regtest genesis creation parameters",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.hashGenesisBlock\s*==\s*uint256\{\"00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac\"\}",
            "regtest: expected FJAR regtest genesis hash",
        )
        self.assert_match(
            regtest_block,
            r"genesis\.hashMerkleRoot\s*==\s*uint256\{\"d610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28\"\}",
            "regtest: expected FJAR regtest genesis merkle root",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.SegwitHeight\s*=\s*0\s*;",
            "regtest: expected SegWit to remain active by default",
        )
        self.assert_match(
            regtest_block,
            r"consensus\.vDeployments\[Consensus::DEPLOYMENT_TAPROOT\]\.nStartTime\s*=\s*Consensus::BIP9Deployment::ALWAYS_ACTIVE\s*;",
            "regtest: expected Taproot deployment to remain always active by default",
        )

        self.assert_match(
            wallet_text,
            r"DEFAULT_ADDRESS_TYPE\s*\{\s*OutputType::LEGACY\s*\}",
            "wallet: expected default address type to remain LEGACY",
        )

        self.assert_match(
            validation_text,
            r"flags\s*\|=\s*SCRIPT_ENABLE_FJARCODE_OPCODES\s*;",
            "validation: expected block script flags to enable SCRIPT_ENABLE_FJARCODE_OPCODES",
        )
        self.assert_match(
            validation_text,
            r"flags\s*\|=\s*SCRIPT_ENABLE_SIGHASH_FORKID\s*;",
            "validation: expected block script flags to enable SCRIPT_ENABLE_SIGHASH_FORKID",
        )
        self.assert_match(
            validation_text,
            r"flags\s*\|=\s*SCRIPT_ENABLE_TOKENS\s*;",
            "validation: expected block script flags to enable SCRIPT_ENABLE_TOKENS",
        )
        self.assert_match(
            validation_text,
            r"flags\s*\|=\s*SCRIPT_ENABLE_VM_LIMITS\s*;",
            "validation: expected block script flags to enable SCRIPT_ENABLE_VM_LIMITS",
        )
        self.assert_match(
            validation_text,
            r"flags\s*\|=\s*SCRIPT_ENABLE_MAY2025\s*;",
            "validation: expected block script flags to enable SCRIPT_ENABLE_MAY2025",
        )
        self.assert_match(
            validation_text,
            r"consensusparams\.FJARCODEActivationHeight\s*!=\s*Consensus::NEVER_ACTIVE_HEIGHT",
            "validation: expected FJARCODEActivationHeight guard for forkid flag wiring",
        )
        self.assert_match(
            validation_text,
            r"consensusparams\.upgrade9Height\s*!=\s*Consensus::NEVER_ACTIVE_HEIGHT",
            "validation: expected upgrade9Height guard for token flag wiring",
        )
        self.assert_match(
            validation_text,
            r"consensusparams\.upgrade10Height\s*!=\s*Consensus::NEVER_ACTIVE_HEIGHT",
            "validation: expected upgrade10Height guard for VM limits flag wiring",
        )
        self.assert_match(
            validation_text,
            r"consensusparams\.upgrade11Height\s*!=\s*Consensus::NEVER_ACTIVE_HEIGHT",
            "validation: expected upgrade11Height guard for MAY2025 flag wiring",
        )
        self.assert_match(
            node_rpc_text,
            r"policy\.pushKV\(\s*\"hard_fork_height\"\s*,\s*consensus\.fjarPolicyHardForkHeight\s*\)",
            "node rpc: expected hard_fork_height policy export to follow consensus.fjarPolicyHardForkHeight",
        )
        self.assert_match(
            node_rpc_text,
            r"policy\.pushKV\(\s*\"checkpoint_height\"\s*,\s*consensus\.fjarPolicyCheckpointHeight\s*\)",
            "node rpc: expected checkpoint_height policy export to follow consensus.fjarPolicyCheckpointHeight",
        )
        self.assert_match(
            node_rpc_text,
            r"activation_matrix\.pushKV\(\s*\"upgrade12\"\s*,\s*consensus\.upgrade12Height\s*\)",
            "node rpc: expected activation_matrix upgrade12 to follow consensus.upgrade12Height",
        )

        self.log.info("FJAR policy + network/address parity contract checks passed")

    def extract_class_block(self, text: str, class_name: str) -> str:
        anchor = f"class {class_name}"
        start = text.find(anchor)
        if start < 0:
            raise AssertionError(f"Missing class block for {class_name}")

        next_class = text.find("\nclass ", start + len(anchor))
        if next_class < 0:
            return text[start:]
        return text[start:next_class]

    def assert_match(self, text: str, pattern: str, message: str):
        if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
            raise AssertionError(message)


if __name__ == "__main__":
    PolicyParityContractTest(__file__).main()
