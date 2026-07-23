// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/v3_policy.h>

std::optional<std::string> SingleV3Checks(const CTransactionRef& ptx,
                                          const CTxMemPool::setEntries& mempool_ancestors,
                                          const std::set<Txid>& direct_conflicts,
                                          int64_t vsize)
{
    const auto truc_result = SingleTRUCChecks(ptx, mempool_ancestors, direct_conflicts, vsize);
    if (!truc_result.has_value()) return std::nullopt;
    return truc_result->first;
}

std::optional<std::string> PackageV3Checks(const CTransactionRef& ptx,
                                           int64_t vsize,
                                           const Package& package,
                                           const CTxMemPool::setEntries& mempool_ancestors)
{
    return PackageTRUCChecks(ptx, vsize, package, mempool_ancestors);
}
