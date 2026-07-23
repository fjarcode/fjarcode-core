#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Freeze Code Quantum unit-test inventory anchors.

This functional-layer guard ensures key Code Quantum matrix tests remain present
in src/test/script_tests.cpp so unit and functional parity checks stay aligned.
"""

from pathlib import Path
import re

from test_framework.test_framework import BitcoinTestFramework


class CodeQuantumTestInventoryContractTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def run_test(self):
        srcdir = Path(self.config["environment"]["SRCDIR"])
        script_tests = srcdir / "src" / "test" / "script_tests.cpp"
        rpc_node = srcdir / "src" / "rpc" / "node.cpp"
        rpc_output_script = srcdir / "src" / "rpc" / "output_script.cpp"
        wallet_rpc_addresses = srcdir / "src" / "wallet" / "rpc" / "addresses.cpp"
        wallet_rpc_registry = srcdir / "src" / "wallet" / "rpc" / "wallet.cpp"
        qt_receive_dialog = srcdir / "src" / "qt" / "receivecoinsdialog.cpp"
        qt_wallet_model = srcdir / "src" / "qt" / "walletmodel.cpp"
        test_runner = srcdir / "test" / "functional" / "test_runner.py"
        text = script_tests.read_text(encoding="utf8")
        rpc_node_text = rpc_node.read_text(encoding="utf8")
        rpc_text = rpc_output_script.read_text(encoding="utf8")
        wallet_addresses_text = wallet_rpc_addresses.read_text(encoding="utf8")
        wallet_registry_text = wallet_rpc_registry.read_text(encoding="utf8")
        qt_receive_text = qt_receive_dialog.read_text(encoding="utf8")
        qt_wallet_model_text = qt_wallet_model.read_text(encoding="utf8")
        runner_text = test_runner.read_text(encoding="utf8")

        self.log.info("Checking Code Quantum test inventory anchors")
        self.assert_match(text, r"BOOST_AUTO_TEST_CASE\(code_quantum_envelope_reason_mapping\)", "Missing code_quantum_envelope_reason_mapping test")
        self.assert_match(text, r"BOOST_AUTO_TEST_CASE\(code_quantum_registry_matrix_frozen\)", "Missing code_quantum_registry_matrix_frozen test")
        self.assert_match(text, r"BOOST_AUTO_TEST_CASE\(code_quantum_mldsa_active_algorithm_failure_mode_consensus_contract\)", "Missing code_quantum_mldsa_active_algorithm_failure_mode_consensus_contract test")
        self.assert_match(text, r"BOOST_AUTO_TEST_CASE\(code_quantum_budget_boundaries_frozen\)", "Missing code_quantum_budget_boundaries_frozen test")
        self.assert_match(text, r"BOOST_AUTO_TEST_CASE\(code_quantum_reject_precedence_frozen\)", "Missing code_quantum_reject_precedence_frozen test")

        self.log.info("Checking that SHA3-256t and reject-precedence scenarios remain represented")
        self.assert_match(text, r"Code Quantum envelope with active SHA3-256t algorithm", "Missing SHA3-256t positive scenario anchor")
        self.assert_match(text, r"Code Quantum SHA3-256t path invalid hashtype rejected", "Missing SHA3-256t invalid hashtype scenario anchor")
        self.assert_match(text, r"Code Quantum reject precedence decode before mode", "Missing reject-precedence scenario anchor")

        self.log.info("Checking Code Quantum RPC surface anchors")
        self.assert_match(rpc_node_text, r"static RPCHelpMan getcodequantuminfo\(\)", "Missing getcodequantuminfo RPC anchor")
        self.assert_match(rpc_node_text, r"\"activation_matrix\"", "Missing getcodequantuminfo activation_matrix policy anchor")
        self.assert_match(rpc_node_text, r"activation_matrix\.pushKV\(\"fjarcode\"", "Missing getcodequantuminfo activation_matrix fjarcode mapping anchor")
        self.assert_match(rpc_node_text, r"activation_matrix\.pushKV\(\"upgrade11\"", "Missing getcodequantuminfo activation_matrix upgrade11 mapping anchor")
        self.assert_match(rpc_node_text, r"\"genesis\"", "Missing getcodequantuminfo genesis policy anchor")
        self.assert_match(rpc_node_text, r"\"reward_sats\"", "Missing getcodequantuminfo genesis reward_sats anchor")
        self.assert_match(rpc_node_text, r"genesis\.pushKV\(\"hash\"", "Missing getcodequantuminfo genesis hash mapping anchor")
        self.assert_match(rpc_node_text, r"\"code_quantum_signing_disabled\"", "Missing getcodequantuminfo signing-disabled capability anchor")
        self.assert_match(rpc_node_text, r"\"code_quantum_signing_verify_only\"", "Missing getcodequantuminfo signing-verify-only capability anchor")
        self.assert_match(rpc_node_text, r"\"code_quantum_signing_enabled\"", "Missing getcodequantuminfo signing-enabled capability anchor")
        self.assert_match(rpc_node_text, r"\"mldsa_65_verify_state\"", "Missing getcodequantuminfo verify-state capability anchor")
        self.assert_match(rpc_node_text, r"\"code_quantum_signing_state\"", "Missing getcodequantuminfo signing-state capability anchor")
        self.assert_match(rpc_text, r"static RPCHelpMan getcodequantumaddress\(\)", "Missing getcodequantumaddress RPC anchor")
        self.assert_match(rpc_text, r"\{\"util\",\s*&getcodequantumaddress\}", "Missing getcodequantumaddress RPC registration")
        self.assert_match(wallet_addresses_text, r"RPCHelpMan getnewquantumaddress\(\)", "Missing getnewquantumaddress wallet RPC anchor")
        self.assert_match(wallet_addresses_text, r"SetAddressBook\(dest,\s*label,\s*AddressPurpose::RECEIVE\)", "Missing getnewquantumaddress address-book receive mapping")
        self.assert_match(wallet_addresses_text, r"requested_address_type == \"quantum\"", "Missing getnewaddress quantum selector branch")
        self.assert_match(wallet_addresses_text, r"RPCArg::DefaultHint\{\"quantum\"\}", "Missing getnewaddress quantum default hint")
        self.assert_match(wallet_registry_text, r"\{\"wallet\",\s*&getnewquantumaddress\}", "Missing getnewquantumaddress wallet RPC registration")
        self.assert_match(qt_receive_text, r"QUANTUM_ADDRESS_TYPE_UI_ID\{-1\}", "Missing Qt quantum UI selector id anchor")
        self.assert_match(qt_receive_text, r"CashAddr \(Quantum\)", "Missing Qt quantum dropdown label anchor")
        self.assert_match(qt_receive_text, r"ui->addressType->setCurrentIndex\(0\)", "Missing Qt quantum default dropdown selection anchor")
        self.assert_match(qt_receive_text, r"getNewQuantumAddress\(label,\s*address,\s*quantum_error\)", "Missing Qt quantum receive RPC bridge usage anchor")
        self.assert_match(qt_wallet_model_text, r"executeRpc\(\"getnewquantumaddress\"", "Missing Qt walletmodel getnewquantumaddress RPC anchor")

        self.log.info("Checking functional CQ contract tests stay registered")
        self.assert_match(runner_text, r"'rpc_code_quantum_info\.py'", "Missing rpc_code_quantum_info.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_address\.py'", "Missing rpc_code_quantum_address.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_help_contract\.py'", "Missing rpc_code_quantum_help_contract.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_info_help_contract\.py'", "Missing rpc_code_quantum_info_help_contract.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_interop_reference_harness\.py'", "Missing rpc_code_quantum_interop_reference_harness.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_mldsa_native_vectors\.py'", "Missing rpc_code_quantum_mldsa_native_vectors.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_regtest_activation_harness\.py'", "Missing rpc_code_quantum_regtest_activation_harness.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_testnet4_chainstart_vectors\.py'", "Missing rpc_code_quantum_testnet4_chainstart_vectors.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_test_inventory_contract\.py'", "Missing rpc_code_quantum_test_inventory_contract.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_info_schema_contract\.py'", "Missing rpc_code_quantum_info_schema_contract.py registration")
        self.assert_match(runner_text, r"'rpc_code_quantum_address_schema_contract\.py'", "Missing rpc_code_quantum_address_schema_contract.py registration")
        self.assert_match(runner_text, r"'rpc_getnewquantumaddress\.py'", "Missing rpc_getnewquantumaddress.py registration")
        self.assert_match(runner_text, r"'rpc_getnewquantumaddress_help_contract\.py'", "Missing rpc_getnewquantumaddress_help_contract.py registration")
        self.assert_match(runner_text, r"'rpc_getnewaddress_quantum_help_contract\.py'", "Missing rpc_getnewaddress_quantum_help_contract.py registration")
        self.assert_match(runner_text, r"'wallet_code_quantum_signing\.py'", "Missing wallet_code_quantum_signing.py registration")

        self.log.info("Code Quantum test inventory contract checks passed")

    def assert_match(self, text: str, pattern: str, message: str):
        if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
            raise AssertionError(message)


if __name__ == "__main__":
    CodeQuantumTestInventoryContractTest(__file__).main()
