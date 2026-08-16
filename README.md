[![GitHub release](https://img.shields.io/github/v/release/fjarcode/fjarcode-core)](https://github.com/fjarcode/fjarcode-core/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
	<img src="share/pixmaps/fjarcode.png" alt="FJARCODE logo" width="140" />
</p>

<h1 align="center"><span style="color:#ef4444;">FJAR</span>CODE</h1>

<p align="center">Mainnet P2P: 28439 | Mainnet RPC: 28442 | CashAddr: fjarcode:</p>

FJARCODE (FJAR) is a cryptocurrency with FJAR consensus rules active from genesis, including 32 MB blocks, ASERT difficulty adjustment, CashAddr addressing, and SegWit disabled.

The chain supports a SHA-256d to SHA3-256t mining transition by configured activation height. On testnet4 and regtest, SHA3-256t is active from the first mined block (height 1), and ASERT retargeting is active from chain start.

FJARCODE also includes the Code Quantum address/runtime path, including ML-DSA-65-oriented provider interfaces and validation contracts used for staged rollout and interoperability testing, aligned with the NIST-standardized ML-DSA family (FIPS 204).

---

## Table of Contents

1. Features
2. System Requirements
3. Build Instructions
4. Hosted Artifacts
5. Configuration
6. Network Information
7. Consensus Activation Summary
8. Code Quantum and ML-DSA-65
9. Hard Fork Policy Notes
10. License

---

## Features

| Feature | Value |
|---------|-------|
| Block Size | 32 MB |
| Difficulty Adjustment | ASERT |
| PoW Algorithms | SHA-256d and SHA3-256t (activation-height controlled) |
| Address Format | CashAddr (fjarcode:q...) |
| Code Quantum | CashAddr quantum type and runtime/provider integration |
| ML-DSA-65 | Active in the runtime algorithm set; native provider pathway and contract-tested dispatch flow (NIST FIPS 204 aligned) |
| ZMQ Notifications | Enabled by default in release builds |
| SegWit | Disabled |
| Coin Symbol | FJAR |

---

## System Requirements

### Minimum
- CPU: 2 cores
- RAM: 4 GB
- Disk: 20 GB SSD
- Network: 10 Mbps

### Recommended
- CPU: 4+ cores
- RAM: 8+ GB
- Disk: 50+ GB SSD
- Network: 100+ Mbps

---

## Build Instructions

The project uses CMake. Typical release-oriented out-of-tree builds are below.

### Linux (native)

```bash
cd /root/fjarcode-v30.0.0
cmake -S . -B build-linux-release-v30 \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_GUI=ON \
	-DBUILD_TESTS=ON
cmake --build build-linux-release-v30 -j"$(nproc)"
```

Main binaries are written under `build-linux-release-v30/bin/`.

### Windows (Win64 cross-build on Linux)

```bash
cd /root/fjarcode-v30.0.0
cmake -S . -B build-win64-release-v30 \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_GUI=ON
cmake --build build-win64-release-v30 -j"$(nproc)"
```

Win64 outputs are written under `build-win64-release-v30/bin/`.

### macOS

```bash
cd /path/to/fjarcode-v30.0.0
cmake -S . -B build-macos-release \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_GUI=ON
cmake --build build-macos-release -j"$(sysctl -n hw.ncpu)"
```

On macOS hosts with Apple toolchains and Qt available, app outputs are generated under `build-macos-release/bin/`.

---

## Hosted Artifacts (v30.0.5)

Download path:

- `/var/www/html/downloads`

Windows:

- `fjarcode-v30.0.5-win64.exe`
- `fjarcoded-v30.0.5-win64.exe`
- `fjarcode-cli-v30.0.5-win64.exe`
- `fjarcode-qt-v30.0.5-win64.exe`
- `fjarcode-qt-v30.0.5-win64.zip`
- `fjarcode-v30.0.5-windows-win64-artifacts.zip`

Linux:

- `fjarcode-v30.0.5-linux-x86_64`
- `fjarcoded-v30.0.5-linux-x86_64`
- `fjarcode-cli-v30.0.5-linux-x86_64`
- `fjarcode-qt-v30.0.5-linux-x86_64`
- `fjarcode-v30.0.5-linux-x86_64-artifacts.tar.gz`

Debian:

- `fjarcode-qt-v30.0.5-linux-amd64.deb`

Source:

- `fjarcode-core-source-v30.0.5-20260816-r1-fullsrc.tar.gz`

Checksums:

- `SHA256SUMS.txt` and per-file `.sha256`

---

## Configuration

Create configuration at ~/.fjarcode/fjarcode.conf:

```ini
# Network
listen=1
maxconnections=125
port=28439

# RPC
server=1
rpcuser=yourusername
rpcpassword=yourpassword
rpcallowip=127.0.0.1
rpcport=28442

# Performance
dbcache=450
maxmempool=300

# Optional prune
# prune=10000
```

### Default Ports by Network

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| Mainnet | 28439 | 28442 |
| Testnet | 29439 | 29442 |
| Testnet4 | 48333 | 48332 |
| Signet | 30439 | 30442 |
| Regtest | 31439 | 31442 |

### Example Network Overrides

```ini
# Testnet
# testnet=1
# port=29439
# rpcport=29442

# Testnet4
# testnet4=1
# port=48333
# rpcport=48332

# Signet
# signet=1
# port=30439
# rpcport=30442

# Regtest
# regtest=1
# port=31439
# rpcport=31442
```

---

## Network Information

### Mainnet

| Parameter | Value |
|-----------|-------|
| P2P Port | 28439 |
| RPC Port | 28442 |
| CashAddr Prefix | fjarcode: |
| Legacy Base58 Prefix | 0x00 |

### Additional Networks

| Network | P2P | RPC | CashAddr Prefix |
|---------|-----|-----|-----------------|
| Testnet | 29439 | 29442 | fjarcodetest |
| Testnet4 | 48333 | 48332 | fjarcodetest4 |
| Signet | 30439 | 30442 | fjarcodesignet |
| Regtest | 31439 | 31442 | fjarcoderegtest |

### DNS Seeds (Mainnet)

- seed01.fjarcode.com
- seed02.fjarcode.com

---

## Consensus Activation Summary

| Network | SHA3 Height | SHA3 Target Spacing | Policy Hard Fork Height | Policy Checkpoint Height |
|---------|-------------|---------------------|--------------------------|--------------------------|
| Mainnet | 21000 | 60 seconds | 108500 | 108300 |
| Testnet | 21000 | 60 seconds | 108500 | 108300 |
| Testnet4 | 1 | 60 seconds | 0 | 0 |
| Signet | 21000 | 60 seconds | never active | never active |
| Regtest | 1 | 60 seconds | 0 | 0 |

Notes:
- Testnet4 is intentionally configured for easy public testing: SHA3 is active from height 1 and ASERT-based retargeting is enabled.
- Regtest is aligned with fast local testing: SHA3 is active from height 1.
- Mainnet/testnet also use ASERT-based retarget behavior.

---

## Code Quantum and ML-DSA-65

- Code Quantum addresses are available via the quantum CashAddr destination type in wallet and RPC flows.
- In this update, Code Quantum is the default address type returned by `getnewaddress`.
- ML-DSA-65 is active in the runtime active algorithm set in the current release.
- Wallet signing state reported by getcodequantuminfo (`disabled`, `verify_only`, `enabled`) is a separate capability status and does not change consensus/runtime algorithm activation.
- The native provider runtime path for ML-DSA-65 is integrated through backend/provider interfaces with deterministic fallback behavior.
- The ML-DSA integration targets the NIST standard track defined in FIPS 204.
- Contract tests freeze callback order, provider registration precedence, and cleanup/reset semantics to protect integration behavior across releases.
- On testnet4, operators can validate post-transition mining behavior immediately: block 1+ uses SHA3 activation rules with ASERT-based retargeting.

### Quantum CashAddr Encoding (Electrum/Indexer Notes)

If you are integrating with an Electrum server, indexer, or explorer, Code Quantum addresses use CashAddr with a dedicated type.

1. Prefix by network:

| Network | Prefix |
|---------|--------|
| Mainnet | `fjarcode` |
| Testnet | `fjarcodetest` |
| Testnet4 | `fjarcodetest4` |
| Signet | `fjarcodesignet` |
| Regtest | `fjarcoderegtest` |

2. CashAddr type mapping:
- Type `0`: P2PKH (20-byte hash)
- Type `1`: P2SH (20-byte hash)
- Type `2`: Code Quantum (32-byte hash)

3. Quantum payload rules:
- Must decode as CashAddr type `2`.
- Payload length must be exactly 32 bytes.
- If payload is not 32 bytes, treat as invalid Quantum address.

4. Script template for Quantum destinations:
- `OP_HASH256 <32-byte-quantum-hash> OP_EQUAL`
- This is the script generated by wallet/RPC for Code Quantum destinations.

5. Parsing behavior:
- Full form with prefix is accepted (for example `fjarcode:...`).
- Prefixless form can also be decoded when it matches the active network prefix rules.

6. Useful RPCs for integration tests:

```bash
# Generate a wallet-managed quantum receive address
fjarcode-cli getnewquantumaddress "cq-receive"

# Build a quantum address from a known 32-byte hash and return scriptPubKey
fjarcode-cli getcodequantumaddress "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
```

7. Electrum indexing hint:
- Index by the scriptPubKey derived from the decoded Quantum payload.
- For Electrum scripthash keys, use the standard Electrum convention:
	SHA256(scriptPubKey) with byte order reversed in hex.

### CLI Wallet Signing Workflow

1. Check runtime capability and signing state:

```bash
fjarcode-cli getcodequantuminfo
```

Look at `capabilities`:
- `mldsa_65_verify_state`: native verify runtime (`available` or `unavailable`).
- `code_quantum_signing_state`: effective wallet/runtime signing state (`disabled`, `verify_only`, or `enabled`).

2. Create or use a quantum destination:

```bash
fjarcode-cli getnewquantumaddress "cq-receive"
```

3. Wallet quantum signing is enabled by default in this release.

```bash
fjarcoded -enablecodequantumsigning=0
```

Use `-enablecodequantumsigning=0` only if you need to force a verify-only operational posture.

4. Sign via wallet RPC as usual:

```bash
fjarcode-cli signrawtransactionwithwallet "<rawhex>"
```

### Current Capability State (v30 Hard-Fork Branch)

- Verify path: active and available for Code Quantum wrapped flows (including ML-DSA-65 algorithm routing under current native/builtin profile).
- Signing path: available and default-on at wallet/runtime level (`-enablecodequantumsigning=1` by default).
- Effective state model exposed by `getcodequantuminfo.capabilities.code_quantum_signing_state`:
	- `disabled`: wallet signing gate is off.
	- `verify_only`: wallet signing gate is on but native signer is unavailable in current runtime.
	- `enabled`: wallet signing gate is on and native signer is available.

### Expected CLI Failure Modes

- `Code Quantum input signing is disabled (-enablecodequantumsigning=1 to enable)`
	- Cause: wallet feature gate was explicitly disabled with `-enablecodequantumsigning=0`.
	- Action: remove the override or restart daemon/wallet process with `-enablecodequantumsigning=1`.

- `Code Quantum signer backend unavailable (runtime is verify-only)`
	- Cause: wallet gate is on, but native signer is not available in current runtime/build profile.
	- Action: use a signing-capable profile/backend, or keep node in verify-only mode.

- `Code Quantum signing failed (malformed key material or unsupported mode)`
	- Cause: signing path reached Code Quantum flow but input key/material or mode contract is invalid for signing.
	- Action: validate redeem script/address type coherence, key availability, and signing mode assumptions.

### GUI Wallet Workflow

- Receive flow: use the `CashAddr (Quantum)` receive type in the wallet receive dialog.
- Spend/sign flow: GUI wallet signing follows the same runtime gate and backend-state rules as CLI.
- Operational guidance: if signing fails, use `getcodequantuminfo` to confirm whether runtime is `disabled`, `verify_only`, or `enabled` before retrying.

---

## Hard Fork Policy Notes

- FJAR consensus rules are active from genesis.
- Mainnet/Testnet policy rollout targets remain 108500/108300.
- Testnet4 and Regtest policy heights are fixed at 0 for immediate post-hardfork policy behavior.
- After SHA3 activation on a network, block headers must carry the SHA3 version bit.

---

## License

FJARCODE Core is released under the terms of the MIT license. See [COPYING](COPYING) for details.
