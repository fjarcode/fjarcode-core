// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fjarcode_fork.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(fjarcode_chain_params_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mainnet_is_fjarcode_from_genesis)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().ToString(),
                      "00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac");
    BOOST_CHECK_EQUAL(consensus.FJARCODEActivationHeight, Consensus::ALWAYS_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(consensus.axionHeight, Consensus::ALWAYS_ACTIVE_HEIGHT);
    BOOST_CHECK(consensus.IsFJARCODEActive(0));
    BOOST_CHECK(consensus.IsASERTActive(0));
    BOOST_CHECK(!consensus.IsSegwitActive(0));
    BOOST_CHECK_EQUAL(consensus.BIP34Height, 1);
    BOOST_CHECK_EQUAL(consensus.BIP65Height, 1);
    BOOST_CHECK_EQUAL(consensus.BIP66Height, 1);
    BOOST_CHECK_EQUAL(consensus.CSVHeight, 1);
    BOOST_CHECK_EQUAL(consensus.SegwitHeight, Consensus::NEVER_ACTIVE_HEIGHT);
}

BOOST_AUTO_TEST_CASE(mainnet_uses_genesis_asert_anchor)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_REQUIRE(consensus.asertAnchorParams.has_value());
    const auto& anchor = *consensus.asertAnchorParams;
    BOOST_CHECK_EQUAL(anchor.nHeight, 0);
    BOOST_CHECK_EQUAL(anchor.nBits, 0x1d00ffffu);
    BOOST_CHECK_EQUAL(anchor.nPrevBlockTime, params->GenesisBlock().nTime - consensus.nPowTargetSpacing);
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_2_DAYS);
    BOOST_CHECK_EQUAL(consensus.nMinimumChainWork, uint256S("0x00"));
    BOOST_CHECK_EQUAL(consensus.defaultAssumeValid, uint256S("0x00"));
}

BOOST_AUTO_TEST_CASE(mainnet_fresh_chain_metadata)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);

    BOOST_CHECK_EQUAL(params->Checkpoints().mapCheckpoints.size(), 1U);
    BOOST_CHECK(params->Checkpoints().mapCheckpoints.contains(0));
    BOOST_CHECK_EQUAL(params->TxData().nTime, 0);
    BOOST_CHECK_EQUAL(params->TxData().nTxCount, 0);
    BOOST_CHECK_EQUAL(params->TxData().dTxRate, 0.0);
}

BOOST_AUTO_TEST_CASE(testnet_and_regtest_are_also_from_genesis)
{
    for (ChainType chain_type : {ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(ArgsManager{}, chain_type);
        const auto& consensus = params->GetConsensus();

        BOOST_CHECK_EQUAL(consensus.FJARCODEActivationHeight, Consensus::ALWAYS_ACTIVE_HEIGHT);
        BOOST_CHECK(consensus.IsFJARCODEActive(0));
        BOOST_CHECK(consensus.IsASERTActive(0));
        BOOST_CHECK(!consensus.IsSegwitActive(0));
        BOOST_REQUIRE(consensus.asertAnchorParams.has_value());
        BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nHeight, 0);
        BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nPrevBlockTime,
                          params->GenesisBlock().nTime - consensus.nPowTargetSpacing);
    }
}

BOOST_AUTO_TEST_CASE(signet_is_fjarcode_from_genesis)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.FJARCODEActivationHeight, Consensus::ALWAYS_ACTIVE_HEIGHT);
    BOOST_CHECK(consensus.IsFJARCODEActive(0));
    BOOST_CHECK(consensus.IsASERTActive(0));
    BOOST_CHECK(!consensus.IsSegwitActive(0));
    BOOST_REQUIRE(consensus.asertAnchorParams.has_value());
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nHeight, 0);
    BOOST_CHECK_EQUAL(consensus.asertAnchorParams->nPrevBlockTime,
                      params->GenesisBlock().nTime - consensus.nPowTargetSpacing);
}

BOOST_AUTO_TEST_CASE(cdf_helper_constants_match_from_genesis_model)
{
    BOOST_CHECK_EQUAL(FJAR::FORK_HEIGHT, Consensus::ALWAYS_ACTIVE_HEIGHT);
    BOOST_CHECK(FJAR::IsForkActive(0));
    BOOST_CHECK(FJAR::IsForkActive(1));
    BOOST_CHECK(!FJAR::IsSegWitAllowed(0));
    BOOST_CHECK_EQUAL(FJAR::GetMaxBlockSize(0), FJAR::MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_SUITE_END()
