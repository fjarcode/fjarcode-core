// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2024-2025 The FJARCODE developers
// Copyright (c) 2025 The FJARCODE developers
// Forked from Bitcoin Core version 0.27.0
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "08/Mar/2026 In silence, FJARCODE begins";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = Consensus::NEVER_ACTIVE_HEIGHT;

        // =========================================================================
        // FJARCODE consensus rules are active from genesis on mainnet.
        // =========================================================================
        consensus.FJARCODEActivationHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.uahfHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.daaHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.magneticAnomalyHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.gravitonHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.phononHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.axionHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade8Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade9Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade10Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade11Height = Consensus::ALWAYS_ACTIVE_HEIGHT;

        consensus.asertAnchorParams = Consensus::ASERTAnchor{
            0,
            0x1d00ffff,
            1772999758,
        };

        // ASERT half-life: fixed at the classic BCHN 2-day setting from genesis.
        consensus.nASERTHalfLife = Consensus::Params::ASERT_HALFLIFE_2_DAYS;
        consensus.nASERTHalfLifeTransitionHeight = Consensus::NEVER_ACTIVE_HEIGHT;

        // Default block size (32MB for BCH)
        consensus.nDefaultConsensusBlockSize = 32000000;

        // BCHN-style automatic finalization (rolling checkpoints)
        // Blocks deeper than this from the tip are finalized and cannot be reorged
        consensus.maxReorgDepth = 10;
        // =========================================================================

        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // Taproot - DISABLED (requires SegWit which FJAR doesn't support)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // Disable TESTDUMMY deployment
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.MinBIP9WarningHeight = 0;

        // Mining/difficulty rules
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb2;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xc2;
        nDefaultPort = 28439;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1773000358, 19815, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac"));
        assert(genesis.hashMerkleRoot == uint256S("0xd610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // Initial public DNS seeds for the FJARCODE mainnet.
        vSeeds.clear();
        vSeeds.emplace_back("seed01.fjarcode.com");
        vSeeds.emplace_back("seed02.fjarcode.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {{
            {0, uint256S("0x00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac")},
        }};

        m_assumeutxo_data = {
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{0, 0, 0};
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        // BIP heights - active from early blocks for fresh FJAR testnet
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = Consensus::NEVER_ACTIVE_HEIGHT;
        consensus.MinBIP9WarningHeight = 0;

        // =========================================================================
        // FJAR Fork Parameters - Active from genesis for fresh testnet
        // =========================================================================
        consensus.FJARCODEActivationHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.uahfHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.daaHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.magneticAnomalyHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.gravitonHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.phononHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.axionHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade8Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade9Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade10Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade11Height = Consensus::ALWAYS_ACTIVE_HEIGHT;

        // ASERT anchor at genesis
        consensus.asertAnchorParams = Consensus::ASERTAnchor{
            0,
            0x1d00ffff,
            1772999758,
        };

        // Default block size (32MB - FJAR standard)
        consensus.nDefaultConsensusBlockSize = 32000000;

        // ASERT half-life: fixed at the classic BCHN 2-day setting from genesis.
        // Testnet mirrors mainnet behavior for realistic testing.
        consensus.nASERTHalfLife = Consensus::Params::ASERT_HALFLIFE_2_DAYS;
        consensus.nASERTHalfLifeTransitionHeight = Consensus::NEVER_ACTIVE_HEIGHT;

        // BCHN-style automatic finalization (rolling checkpoints)
        consensus.maxReorgDepth = 10;
        // =========================================================================

        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        // Taproot - DISABLED (requires SegWit which FJAR doesn't support)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        // FJAR testnet-specific magic (avoids collision with Bitcoin Core testnet3)
        pchMessageStart[0] = 0xb2;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0x0b;
        pchMessageStart[3] = 0x11;
        nDefaultPort = 29439;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 42;
        m_assumed_chain_state_size = 3;

        genesis = CreateGenesisBlock(1773000358, 19815, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac"));
        assert(genesis.hashMerkleRoot == uint256S("0xd610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // FJAR DISABLED: vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch.");
        // FJAR DISABLED: vSeeds.emplace_back("seed.tbtc.petertodd.net.");
        // FJAR DISABLED: vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl.");
        // FJAR DISABLED: vSeeds.emplace_back("testnet-seed.bluematt.me.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {{
            {0, uint256S("0x00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac")},
        }};

        // FJAR testnet: no assumeutxo data yet (fresh chain)
        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            // FJAR testnet: no historical data yet
            .nTime    = 0,
            .nTxCount = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            // FJAR DISABLED: vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");

            // Hardcoded nodes can be removed once there are more DNS seeds
            // FJAR DISABLED: vSeeds.emplace_back("178.128.221.177");
            // FJAR DISABLED: vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x00");
            consensus.defaultAssumeValid = uint256S("0x00");
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000000870f15246ba23c16e370a7ffb1fc8a3dcf8cb4492882ed4b0e3d4cd26
                .nTime    = 1706331472,
                .nTxCount = 2425380,
                .dTxRate  = 0.008277759863833788,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = Consensus::NEVER_ACTIVE_HEIGHT;

        // =========================================================================
        // FJAR rules are active from genesis on signet as well.
        // =========================================================================
        consensus.FJARCODEActivationHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.uahfHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.daaHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.magneticAnomalyHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.gravitonHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.phononHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.axionHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade8Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade9Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade10Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade11Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.asertAnchorParams = Consensus::ASERTAnchor{0, 0x1d00ffff, 1773000358 - consensus.nPowTargetSpacing};
        consensus.nDefaultConsensusBlockSize = 32000000;

        // ASERT half-life: fixed at the classic BCHN 2-day setting from genesis.
        consensus.nASERTHalfLife = Consensus::Params::ASERT_HALFLIFE_2_DAYS;
        consensus.nASERTHalfLifeTransitionHeight = Consensus::NEVER_ACTIVE_HEIGHT;
        // =========================================================================

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000377ae000000000000000000000000000000000000000000000000000000");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        // Taproot - DISABLED (requires SegWit which FJAR doesn't support)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 30439;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1773000358, 19815, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac"));
        assert(genesis.hashMerkleRoot == uint256S("0xd610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28"));

        vFixedSeeds.clear();

        checkpointData = {{
            {0, uint256S("0x00000000e7b81419d4934b9f9bad6aa432b3eb853b70c8db1f36addb6605ddac")},
        }};

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = Consensus::NEVER_ACTIVE_HEIGHT;
        consensus.MinBIP9WarningHeight = 0;

        // =========================================================================
        // FJAR rules are active from genesis by default on regtest.
        // Buried deployment overrides remain available via RegTestOptions.
        // =========================================================================
        consensus.FJARCODEActivationHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.uahfHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.daaHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.magneticAnomalyHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.gravitonHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.phononHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.axionHeight = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade8Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade9Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade10Height = Consensus::ALWAYS_ACTIVE_HEIGHT;
        consensus.upgrade11Height = Consensus::ALWAYS_ACTIVE_HEIGHT;

        consensus.asertAnchorParams = Consensus::ASERTAnchor{
            0,
            0x207fffff,
            1772995755,
        };

        // Default block size (32MB for BCH mode)
        consensus.nDefaultConsensusBlockSize = 32000000;

        // ASERT half-life: fixed at the classic BCHN 2-day setting from genesis.
        consensus.nASERTHalfLife = Consensus::Params::ASERT_HALFLIFE_2_DAYS;
        consensus.nASERTHalfLifeTransitionHeight = Consensus::NEVER_ACTIVE_HEIGHT;

        // BCHN-style automatic finalization (rolling checkpoints)
        // High value for regtest to allow deep reorg testing while still
        // exercising the finalization code path. Mainnet/testnet use 10.
        consensus.maxReorgDepth = 10000;
        // =========================================================================

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        // Taproot - DISABLED (requires SegWit which FJAR doesn't support)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xb2;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xfa;
        pchMessageStart[3] = 0xbf;
        nDefaultPort = 31439;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // low nonce works with this easy difficulty
        genesis = CreateGenesisBlock(1772996355, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4f5fcc6dc0eeb697862152f1127bd8683db681a5dcedf185cc6f8bb6519f1527"));
        assert(genesis.hashMerkleRoot == uint256S("0xd610ff1b56351701124fccb1e4a33cc778d0d4f7a600c1fa290261923fbe2f28"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        // FJAR DISABLED: vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("4f5fcc6dc0eeb697862152f1127bd8683db681a5dcedf185cc6f8bb6519f1527")},
            }
        };

        m_assumeutxo_data = {};

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}
