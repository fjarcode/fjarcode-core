# FJARCODE (FJAR) Core

**Version 27.0.0** | Mainnet P2P: 28439 | Mainnet RPC: 28442 | CashAddr: `fjarcode:`

FJARCODE (FJAR) is a SHA-256 cryptocurrency with FJARCODE consensus rules active from genesis, including 32 MB blocks, classic BCHN ASERT difficulty adjustment with the aserti3-2d 2-day half-life from genesis, CashAddr addressing, and SegWit disabled.

---

## Table of Contents

1. [Features](#features)
2. [System Requirements](#system-requirements)
3. [Download Pre-built Binaries](#download-pre-built-binaries)
4. [Configuration](#configuration)
5. [Network Information](#network-information)
6. [License](#license)

---

## Features

| Feature | Value |
|---------|-------|
| Block Size | 32 MB |
| Block Time | 10 minutes |
| Difficulty Adjustment | ASERT (aserti3-2d, 2-day half-life from genesis) |
| Address Format | CashAddr (`fjarcode:q...`) |
| SegWit | Disabled |
| Coin Symbol | FJAR |

---

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 20 GB SSD
- **Network**: 10 Mbps

### Recommended Requirements
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Disk**: 50+ GB SSD
- **Network**: 100+ Mbps

---

## Download Pre-built Binaries

Download the latest release from: https://github.com/fjarcode/fjarcode-core/releases

---

## Configuration

Create a configuration file at `~/.fjarcode/fjarcode.conf`:

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

# Optional: Prune old blocks (saves disk space)
# prune=10000
```

### Default Ports by Network

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| Mainnet | 28439 | 28442 |
| Testnet | 29439 | 29442 |
| Signet | 30439 | 30442 |
| Regtest | 31439 | 31442 |

### Example Network Overrides

```ini
# Testnet
# testnet=1
# port=29439
# rpcport=29442

# Signet
# signet=1
# port=30439
# rpcport=30442

# Regtest
# regtest=1
# port=31439
# rpcport=31442
```

### Data Directory Locations

| OS | Default Location |
|----|------------------|
| Linux | `~/.fjarcode/` |
| macOS | `~/Library/Application Support/FJARCODE/` |
| Windows | `%APPDATA%\FJARCODE\` |

---

## Network Information

### Mainnet

| Parameter | Value |
|-----------|-------|
| P2P Port | 28439 |
| RPC Port | 28442 |
| CashAddr Prefix | `fjarcode:` |
| Legacy Base58 Prefix | `0x00` |

### Additional Networks

| Network | P2P Port | RPC Port | Notes |
|---------|----------|----------|-------|
| Testnet | 29439 | 29442 | Public test network |
| Signet | 30439 | 30442 | Signed test network |
| Regtest | 31439 | 31442 | Local private development chain |

### DNS Seeds

- `seed01.fjarcode.com`
- `seed02.fjarcode.com`

### Manual Peer Example

```bash
./fjarcode-cli addnode "seed01.fjarcode.com:28439" "add"
```

---

## License

FJARCODE Core is released under the terms of the MIT license. See [COPYING](COPYING) for more information.
