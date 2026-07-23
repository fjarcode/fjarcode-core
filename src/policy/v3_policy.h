// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_V3_POLICY_H
#define BITCOIN_POLICY_V3_POLICY_H

#include <policy/truc_policy.h>

/**
 * Legacy v3-policy compatibility surface.
 *
 * The BTC30 codebase uses TRUC terminology for version=3 transaction policy.
 * This header preserves the older v3 entry points used by legacy FJARCODE
 * deltas by forwarding behavior to TRUC checks.
 */
static constexpr unsigned int V3_DESCENDANT_LIMIT{TRUC_DESCENDANT_LIMIT};
static constexpr unsigned int V3_ANCESTOR_LIMIT{TRUC_ANCESTOR_LIMIT};
static constexpr int64_t V3_CHILD_MAX_VSIZE{TRUC_CHILD_MAX_VSIZE};

std::optional<std::string> SingleV3Checks(const CTransactionRef& ptx,
                                          const CTxMemPool::setEntries& mempool_ancestors,
                                          const std::set<Txid>& direct_conflicts,
                                          int64_t vsize);

std::optional<std::string> PackageV3Checks(const CTransactionRef& ptx,
                                           int64_t vsize,
                                           const Package& package,
                                           const CTxMemPool::setEntries& mempool_ancestors);

#endif // BITCOIN_POLICY_V3_POLICY_H
