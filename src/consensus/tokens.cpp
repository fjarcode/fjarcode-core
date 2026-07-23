// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tokens.h>

TokenValidationResult CheckTokens(const CTransaction& tx,
                                  const std::vector<CTxOut>& spent_outputs,
                                  bool require_tokens)
{
    (void)tx;
    (void)spent_outputs;
    (void)require_tokens;
    // Token primitives are not ported in this tree yet.
    return TokenValidationResult::Ok();
}

bool IsTokenGenesis(const CTransaction& tx)
{
    (void)tx;
    return false;
}

uint256 GetGenesisCategoryId(const CTransaction& tx)
{
    if (tx.vin.empty()) return uint256{};
    return tx.vin[0].prevout.hash.ToUint256();
}

bool HasTokenOutputs(const CTransaction& tx)
{
    (void)tx;
    return false;
}

bool HasTokenInputs(const std::vector<CTxOut>& spent_outputs)
{
    (void)spent_outputs;
    return false;
}
