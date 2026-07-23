// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_TOKENS_H
#define BITCOIN_CONSENSUS_TOKENS_H

#include <primitives/transaction.h>

#include <string>
#include <vector>

/**
 * Temporary token-validation surface for Phase 5 parity scaffolding.
 *
 * This BTC30 migration tree does not yet carry token primitives on CTxOut,
 * so these helpers intentionally behave as no-op/false until token script
 * and transaction data structures are ported.
 */
struct TokenValidationResult {
    bool valid{true};
    std::string error;

    TokenValidationResult() = default;
    explicit TokenValidationResult(const std::string& err) : valid(false), error(err) {}

    static TokenValidationResult Ok() { return TokenValidationResult(); }
    static TokenValidationResult Error(const std::string& msg) { return TokenValidationResult(msg); }

    operator bool() const { return valid; }
};

TokenValidationResult CheckTokens(const CTransaction& tx,
                                  const std::vector<CTxOut>& spent_outputs,
                                  bool require_tokens = true);

bool IsTokenGenesis(const CTransaction& tx);
uint256 GetGenesisCategoryId(const CTransaction& tx);
bool HasTokenOutputs(const CTransaction& tx);
bool HasTokenInputs(const std::vector<CTxOut>& spent_outputs);

#endif // BITCOIN_CONSENSUS_TOKENS_H
