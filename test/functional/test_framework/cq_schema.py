#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Shared helpers for Code Quantum RPC schema contract tests."""


def assert_exact_keys(obj: dict, expected_keys: list[str], where: str):
    actual = sorted(obj.keys())
    expected = sorted(expected_keys)
    assert actual == expected, f"{where}: expected keys {expected}, got {actual}"


def assert_type(value, expected_type, where: str):
    assert isinstance(value, expected_type), f"{where}: expected {expected_type.__name__}, got {type(value).__name__}"
