// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/params.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(fjarcode_fork_boundary_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(regtest_has_no_pre_fork_boundary_anymore)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.FJARCODEActivationHeight, Consensus::ALWAYS_ACTIVE_HEIGHT);
    BOOST_CHECK(consensus.IsFJARCODEActive(0));
    BOOST_CHECK(consensus.IsFJARCODEActive(1));
    BOOST_CHECK(consensus.IsUAHFActive(0));
    BOOST_CHECK(consensus.IsDAAActive(0));
    BOOST_CHECK(consensus.IsMagneticAnomalyActive(0));
    BOOST_CHECK(consensus.IsGravitonActive(0));
    BOOST_CHECK(consensus.IsPhononActive(0));
    BOOST_CHECK(consensus.IsASERTActive(0));
    BOOST_CHECK(consensus.IsUpgrade8Active(0));
    BOOST_CHECK(consensus.IsUpgrade9Active(0));
    BOOST_CHECK(consensus.IsUpgrade10Active(0));
    BOOST_CHECK(consensus.IsUpgrade11Active(0));
}

BOOST_AUTO_TEST_CASE(segwit_is_disabled_from_genesis_on_fjarcode_chains)
{
    for (ChainType chain_type : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(ArgsManager{}, chain_type);
        const auto& consensus = params->GetConsensus();
        BOOST_CHECK(!consensus.IsSegwitActive(0));
        BOOST_CHECK(!consensus.IsSegwitActive(1));
    }
}

BOOST_AUTO_TEST_CASE(asert_anchor_no_longer_waits_for_first_post_fork_block)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    BOOST_REQUIRE(consensus.asertAnchorParams.has_value());
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nHeight, 0);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nBits, params->GenesisBlock().nBits);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nPrevBlockTime,
                      params->GenesisBlock().nTime - consensus.nPowTargetSpacing);
}

BOOST_AUTO_TEST_CASE(post_fork_policy_flags_are_now_baseline_policy)
{
    BOOST_CHECK(FJARCODE_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SIGHASH_FORKID);
    BOOST_CHECK(FJARCODE_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_NO_SEGWIT);
    BOOST_CHECK(!(FJARCODE_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
}

BOOST_AUTO_TEST_SUITE_END()
