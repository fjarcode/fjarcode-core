// Copyright (c) 2025 FJAR Developers
// Distributed under the MIT software license
// FJAR Fork from FJAR - Network Parameters

#ifndef FJARCODE_FORK_H
#define FJARCODE_FORK_H

#include <cstdint>

namespace FJAR {

//
// Fork Configuration
//

// Fjarcode rules are active from genesis.
static constexpr int FORK_HEIGHT = -1;

// Network identification
static constexpr unsigned char MAGIC[4] = {0xb2, 0xc2, 0xb2, 0xc2};
static constexpr int P2P_PORT = 28439;
static constexpr int RPC_PORT = 28442;

//
// Fjarcode consensus rules
//

// Block size: 32MB (BCH standard) — matches FJARCODE_MAX_BLOCK_SIZE in consensus.h
static constexpr uint64_t MAX_BLOCK_SIZE = 32000000;

// SIGHASH_FORKID for replay protection
static constexpr uint32_t SIGHASH_FORKID = 0x40;
static constexpr uint32_t FORKID = 0;

//
// Helper Functions
//

// Are Fjarcode rules active at this height?
inline bool IsForkActive(int height) {
    return height > FORK_HEIGHT;
}

// Is SegWit allowed at this height?
// No on Fjarcode chains, since FJAR rules are active from genesis.
inline bool IsSegWitAllowed(int height) {
    return height <= FORK_HEIGHT;
}

// Get max block size for height
inline uint64_t GetMaxBlockSize(int height) {
    if (IsForkActive(height)) {
        return MAX_BLOCK_SIZE;
    }
    return 4 * 1024 * 1024;
}

} // namespace FJAR

#endif // FJARCODE_FORK_H
