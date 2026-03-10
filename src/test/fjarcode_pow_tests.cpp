// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

arith_uint256 GetMainnetPowLimit()
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    return UintToArith256(params->GetConsensus().powLimit);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fjarcode_pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(asert_no_change_at_perfect_spacing)
{
    const arith_uint256 pow_limit = GetMainnetPowLimit();
    const arith_uint256 ref_target = pow_limit >> 4;
    const int64_t target_spacing = 600;
    const int64_t half_life = 3600;
    const int64_t height_diff = 10;
    const int64_t time_diff = target_spacing * (height_diff + 1);

    const arith_uint256 result = CalculateASERT(ref_target, target_spacing, time_diff, height_diff, pow_limit, half_life);
    const arith_uint256 diff = result > ref_target ? result - ref_target : ref_target - result;
    BOOST_CHECK(diff * 10000 < ref_target);
}

BOOST_AUTO_TEST_CASE(asert_adjusts_in_expected_direction)
{
    const arith_uint256 pow_limit = GetMainnetPowLimit();
    const arith_uint256 ref_target = pow_limit >> 4;

    const arith_uint256 fast = CalculateASERT(ref_target, 600, 3300, 10, pow_limit, 3600);
    const arith_uint256 slow = CalculateASERT(ref_target, 600, 13200, 10, pow_limit, 3600);

    BOOST_CHECK(fast < ref_target);
    BOOST_CHECK(slow > ref_target);
}

BOOST_AUTO_TEST_CASE(mainnet_permitted_transition_uses_asert_from_block_zero)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    arith_uint256 easier_target = pow_limit;
    easier_target >>= 1;
    const uint32_t old_bits = pow_limit.GetCompact();
    const uint32_t new_bits = easier_target.GetCompact();

    BOOST_CHECK(consensus.IsASERTActive(0));
    BOOST_CHECK(PermittedDifficultyTransition(consensus, 0, old_bits, new_bits));
    BOOST_CHECK(PermittedDifficultyTransition(consensus, 1, old_bits, new_bits));
}

BOOST_AUTO_TEST_CASE(mainnet_anchor_is_genesis_based)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_REQUIRE(consensus.asertAnchorParams.has_value());
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nHeight, 0);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nBits, params->GenesisBlock().nBits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nPrevBlockTime,
                      params->GenesisBlock().nTime - consensus.nPowTargetSpacing);
}

BOOST_AUTO_TEST_CASE(signet_uses_asert_from_genesis)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& consensus = params->GetConsensus();
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    arith_uint256 easier_target = pow_limit;
    easier_target >>= 1;
    const uint32_t old_bits = params->GenesisBlock().nBits;
    const uint32_t new_bits = easier_target.GetCompact();

    BOOST_CHECK(consensus.IsASERTActive(0));
    BOOST_CHECK(consensus.IsASERTActive(1));
    BOOST_CHECK(PermittedDifficultyTransition(consensus, 1, old_bits, new_bits));
}

BOOST_AUTO_TEST_SUITE_END()
