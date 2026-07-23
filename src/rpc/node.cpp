// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <common/args.h>
#include <httpserver.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <index/txindex.h>
#include <interfaces/chain.h>
#include <interfaces/echo.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/code_quantum_mldsa_backend_native.h>
#include <script/code_quantum_params.h>
#include <univalue.h>
#include <util/any.h>
#include <util/check.h>
#include <util/time.h>

#include <cstdint>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

using node::NodeContext;

static RPCHelpMan setmocktime()
{
    return RPCHelpMan{
        "setmocktime",
        "Set the local time to given timestamp (-regtest only)\n",
        {
            {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, UNIX_EPOCH_TIME + "\n"
             "Pass 0 to go back to using the system time."},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().IsMockableChain()) {
        throw std::runtime_error("setmocktime is for regression testing (-regtest mode) only");
    }

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    const int64_t time{request.params[0].getInt<int64_t>()};
    constexpr int64_t max_time{Ticks<std::chrono::seconds>(std::chrono::nanoseconds::max())};
    if (time < 0 || time > max_time) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Mocktime must be in the range [0, %s], not %s.", max_time, time));
    }

    SetMockTime(time);
    const NodeContext& node_context{EnsureAnyNodeContext(request.context)};
    for (const auto& chain_client : node_context.chain_clients) {
        chain_client->setMockTime(time);
    }

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan mockscheduler()
{
    return RPCHelpMan{
        "mockscheduler",
        "Bump the scheduler into the future (-regtest only)\n",
        {
            {"delta_time", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of seconds to forward the scheduler into the future." },
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!Params().IsMockableChain()) {
        throw std::runtime_error("mockscheduler is for regression testing (-regtest mode) only");
    }

    int64_t delta_seconds = request.params[0].getInt<int64_t>();
    if (delta_seconds <= 0 || delta_seconds > 3600) {
        throw std::runtime_error("delta_time must be between 1 and 3600 seconds (1 hr)");
    }

    const NodeContext& node_context{EnsureAnyNodeContext(request.context)};
    CHECK_NONFATAL(node_context.scheduler)->MockForward(std::chrono::seconds{delta_seconds});
    CHECK_NONFATAL(node_context.validation_signals)->SyncWithValidationInterfaceQueue();
    for (const auto& chain_client : node_context.chain_clients) {
        chain_client->schedulerMockForward(std::chrono::seconds(delta_seconds));
    }

    return UniValue::VNULL;
},
    };
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

static RPCHelpMan getmemoryinfo()
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    return RPCHelpMan{"getmemoryinfo",
                "Returns an object containing information about memory usage.\n",
                {
                    {"mode", RPCArg::Type::STR, RPCArg::Default{"stats"}, "determines what kind of information is returned.\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc)."},
                },
                {
                    RPCResult{"mode \"stats\"",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::OBJ, "locked", "Information about locked memory manager",
                            {
                                {RPCResult::Type::NUM, "used", "Number of bytes used"},
                                {RPCResult::Type::NUM, "free", "Number of bytes available in current arenas"},
                                {RPCResult::Type::NUM, "total", "Total number of bytes managed"},
                                {RPCResult::Type::NUM, "locked", "Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk."},
                                {RPCResult::Type::NUM, "chunks_used", "Number allocated chunks"},
                                {RPCResult::Type::NUM, "chunks_free", "Number unused chunks"},
                            }},
                        }
                    },
                    RPCResult{"mode \"mallocinfo\"",
                        RPCResult::Type::STR, "", "\"<malloc version=\"1\">...\""
                    },
                },
                RPCExamples{
                    HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("locked", RPCLockedMemoryInfo());
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo mode not available");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
},
    };
}

static void EnableOrDisableLogCategories(UniValue cats, bool enable) {
    cats = cats.get_array();
    for (unsigned int i = 0; i < cats.size(); ++i) {
        std::string cat = cats[i].get_str();

        bool success;
        if (enable) {
            success = LogInstance().EnableCategory(cat);
        } else {
            success = LogInstance().DisableCategory(cat);
        }

        if (!success) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
    }
}

static RPCHelpMan logging()
{
    return RPCHelpMan{"logging",
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + LogInstance().LogCategoriesString() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            ,
                {
                    {"include", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The categories to add to debug logging",
                        {
                            {"include_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                    {"exclude", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The categories to remove from debug logging",
                        {
                            {"exclude_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "keys are the logging categories, and values indicates its status",
                    {
                        {RPCResult::Type::BOOL, "category", "if being debug logged or not. false:inactive, true:active"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], [\"libevent\"]")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    BCLog::CategoryMask original_log_categories = LogInstance().GetCategoryMask();
    if (request.params[0].isArray()) {
        EnableOrDisableLogCategories(request.params[0], true);
    }
    if (request.params[1].isArray()) {
        EnableOrDisableLogCategories(request.params[1], false);
    }
    BCLog::CategoryMask updated_log_categories = LogInstance().GetCategoryMask();
    BCLog::CategoryMask changed_log_categories = original_log_categories ^ updated_log_categories;

    // Update libevent logging if BCLog::LIBEVENT has changed.
    if (changed_log_categories & BCLog::LIBEVENT) {
        UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT));
    }

    UniValue result(UniValue::VOBJ);
    for (const auto& logCatActive : LogInstance().LogCategoriesList()) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
},
    };
}

static RPCHelpMan echo(const std::string& name)
{
    return RPCHelpMan{
        name,
        "Simply echo back the input arguments. This command is for testing.\n"
                "\nIt will return an internal bug report when arg9='trigger_internal_bug' is passed.\n"
                "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in "
                "bitcoin-cli and the GUI. There is no server-side difference.",
        {
            {"arg0", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg1", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg2", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg3", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg4", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg5", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg6", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg7", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg8", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
            {"arg9", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "", RPCArgOptions{.skip_type_check = true}},
        },
                RPCResult{RPCResult::Type::ANY, "", "Returns whatever was passed in"},
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (request.params[9].isStr()) {
        CHECK_NONFATAL(request.params[9].get_str() != "trigger_internal_bug");
    }

    return request.params;
},
    };
}

static RPCHelpMan echo() { return echo("echo"); }
static RPCHelpMan echojson() { return echo("echojson"); }

static RPCHelpMan echoipc()
{
    return RPCHelpMan{
        "echoipc",
        "Echo back the input argument, passing it through a spawned process in a multiprocess build.\n"
        "This command is for testing.\n",
        {{"arg", RPCArg::Type::STR, RPCArg::Optional::NO, "The string to echo",}},
        RPCResult{RPCResult::Type::STR, "echo", "The echoed string."},
        RPCExamples{HelpExampleCli("echo", "\"Hello world\"") +
                    HelpExampleRpc("echo", "\"Hello world\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            interfaces::Init& local_init = *EnsureAnyNodeContext(request.context).init;
            std::unique_ptr<interfaces::Echo> echo;
            if (interfaces::Ipc* ipc = local_init.ipc()) {
                // Spawn a new bitcoin-node process and call makeEcho to get a
                // client pointer to a interfaces::Echo instance running in
                // that process. This is just for testing. A slightly more
                // realistic test spawning a different executable instead of
                // the same executable would add a new bitcoin-echo executable,
                // and spawn bitcoin-echo below instead of bitcoin-node. But
                // using bitcoin-node avoids the need to build and install a
                // new executable just for this one test.
                auto init = ipc->spawnProcess("bitcoin-node");
                echo = init->makeEcho();
                ipc->addCleanup(*echo, [init = init.release()] { delete init; });
            } else {
                // IPC support is not available because this is a bitcoind
                // process not a bitcoind-node process, so just create a local
                // interfaces::Echo object and return it so the `echoipc` RPC
                // method will work, and the python test calling `echoipc`
                // can expect the same result.
                echo = local_init.makeEcho();
            }
            return echo->echo(request.params[0].get_str());
        },
    };
}

static UniValue SummaryToJSON(const IndexSummary&& summary, std::string index_name)
{
    UniValue ret_summary(UniValue::VOBJ);
    if (!index_name.empty() && index_name != summary.name) return ret_summary;

    UniValue entry(UniValue::VOBJ);
    entry.pushKV("synced", summary.synced);
    entry.pushKV("best_block_height", summary.best_block_height);
    ret_summary.pushKV(summary.name, std::move(entry));
    return ret_summary;
}

static RPCHelpMan getindexinfo()
{
    return RPCHelpMan{
        "getindexinfo",
        "Returns the status of one or all available indices currently running in the node.\n",
        {
            {"index_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter results for an index with a specific name."},
        },
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "", {
                {
                    RPCResult::Type::OBJ, "name", "The name of the index",
                    {
                        {RPCResult::Type::BOOL, "synced", "Whether the index is synced or not"},
                        {RPCResult::Type::NUM, "best_block_height", "The block height to which the index is synced"},
                    }
                },
            },
        },
        RPCExamples{
            HelpExampleCli("getindexinfo", "")
                + HelpExampleRpc("getindexinfo", "")
                + HelpExampleCli("getindexinfo", "txindex")
                + HelpExampleRpc("getindexinfo", "txindex")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    const std::string index_name = request.params[0].isNull() ? "" : request.params[0].get_str();

    if (g_txindex) {
        result.pushKVs(SummaryToJSON(g_txindex->GetSummary(), index_name));
    }

    if (g_coin_stats_index) {
        result.pushKVs(SummaryToJSON(g_coin_stats_index->GetSummary(), index_name));
    }

    ForEachBlockFilterIndex([&result, &index_name](const BlockFilterIndex& index) {
        result.pushKVs(SummaryToJSON(index.GetSummary(), index_name));
    });

    return result;
},
    };
}

static RPCHelpMan getcodequantuminfo()
{
    return RPCHelpMan{
        "getcodequantuminfo",
        "Returns Code Quantum runtime status and currently active registry/budget profile.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "enabled", "Whether Code Quantum runtime dispatch is enabled in this build."},
                {RPCResult::Type::NUM, "mode_wrapped_ecdsa", "Current mode ID for wrapped ECDSA Code Quantum envelope."},
                {RPCResult::Type::OBJ, "algorithms", "Code Quantum algorithm ID registry.",
                {
                    {RPCResult::Type::NUM, "wrapped_ecdsa_der", "Legacy wrapped ECDSA DER algorithm ID."},
                    {RPCResult::Type::NUM, "sha3_256t", "SHA3-256t wrapped ECDSA algorithm ID."},
                    {RPCResult::Type::NUM, "mldsa_65", "Reserved ML-DSA-65 algorithm ID (known, not yet active in runtime dispatch)."},
                }},
                {RPCResult::Type::ARR, "active_algorithms", "Algorithm IDs currently active in runtime dispatch.",
                {
                    {RPCResult::Type::NUM, "algorithm_id", "Active algorithm ID."},
                }},
                {RPCResult::Type::OBJ, "capabilities", "Code Quantum runtime capability flags.",
                {
                    {RPCResult::Type::BOOL, "mldsa_65_runtime_enabled", "Whether ML-DSA-65 runtime signature dispatch is enabled."},
                    {RPCResult::Type::BOOL, "mldsa_65_native_verify_available", "Whether native ML-DSA-65 verify dispatch is currently available."},
                    {RPCResult::Type::STR, "mldsa_65_verify_state", "Native ML-DSA-65 verify runtime state: \"available\" or \"unavailable\"."},
                    {RPCResult::Type::BOOL, "mldsa_65_native_signing_available", "Whether native ML-DSA-65 signing dispatch is currently available."},
                    {RPCResult::Type::BOOL, "code_quantum_signing_disabled", "Whether wallet-level Code Quantum signing is disabled by feature flag."},
                    {RPCResult::Type::BOOL, "code_quantum_signing_verify_only", "Whether wallet-level Code Quantum signing is enabled but runtime remains verify-only (native signer unavailable)."},
                    {RPCResult::Type::BOOL, "code_quantum_signing_enabled", "Whether wallet-level Code Quantum signing is enabled and native signing dispatch is available."},
                    {RPCResult::Type::STR, "code_quantum_signing_state", "Effective wallet/runtime Code Quantum signing state: \"disabled\", \"verify_only\", or \"enabled\"."},
                    {RPCResult::Type::BOOL, "external_backend_scaffold_enabled", "Whether external ML-DSA backend scaffold mode is compiled in."},
                    {RPCResult::Type::BOOL, "external_backend_header_detected", "Whether the configured external backend header probe was detected at build time."},
                    {RPCResult::Type::BOOL, "external_backend_verify_api_declared", "Whether the expected external verify API declaration was detected at build time."},
                    {RPCResult::Type::BOOL, "external_backend_verify_linked", "Whether the external verify API symbol link probe succeeded at build time."},
                    {RPCResult::Type::BOOL, "external_backend_bridge_ready", "Whether the external backend bridge is ready for runtime verify dispatch."},
                }},
                {RPCResult::Type::OBJ, "limits", "Code Quantum envelope budget limits.",
                {
                    {RPCResult::Type::NUM, "max_wrapped_sig_size", "Maximum wrapped signature size in bytes."},
                    {RPCResult::Type::NUM, "max_envelope_size", "Maximum envelope size in bytes."},
                }},
                {RPCResult::Type::OBJ, "policy", "Active chain policy summary relevant to FJAR parity.",
                {
                    {RPCResult::Type::STR, "chain", "Current chain type (main/testnet/testnet4/signet/regtest)."},
                    {RPCResult::Type::OBJ, "genesis", "Genesis/block0 profile for the active chain.",
                    {
                        {RPCResult::Type::STR, "hash", "Genesis block hash."},
                        {RPCResult::Type::STR, "merkle_root", "Genesis block merkle root."},
                        {RPCResult::Type::NUM, "time", "Genesis block timestamp (nTime)."},
                        {RPCResult::Type::NUM, "nonce", "Genesis block nonce (nNonce)."},
                        {RPCResult::Type::NUM, "bits", "Genesis block compact target (nBits)."},
                        {RPCResult::Type::NUM, "version", "Genesis block version (nVersion)."},
                        {RPCResult::Type::NUM, "reward_sats", "Genesis coinbase reward in satoshis."},
                    }},
                    {RPCResult::Type::NUM, "default_consensus_block_size", "Default consensus block size in bytes."},
                    {RPCResult::Type::NUM, "pow_target_spacing", "Configured pre-SHA3 target spacing in seconds."},
                    {RPCResult::Type::NUM, "pow_target_spacing_sha3", "Configured post-SHA3 target spacing in seconds."},
                    {RPCResult::Type::NUM, "sha3_height", "Configured SHA3 PoW activation height (or NEVER_ACTIVE_HEIGHT when disabled)."},
                    {RPCResult::Type::NUM, "sha3_version_bit", "Required block-version bit mask once SHA3 PoW is active."},
                    {RPCResult::Type::NUM, "hard_fork_height", "Configured FJAR policy hard-fork anchor height (or NEVER_ACTIVE_HEIGHT when unset)."},
                    {RPCResult::Type::NUM, "checkpoint_height", "Configured FJAR policy checkpoint/finalization anchor height (or NEVER_ACTIVE_HEIGHT when unset)."},
                    {RPCResult::Type::OBJ, "activation_matrix", "FJAR activation-height matrix for consensus feature gates.",
                    {
                        {RPCResult::Type::NUM, "fjarcode", "Base FJARCODE activation height."},
                        {RPCResult::Type::NUM, "uahf", "UAHF activation height."},
                        {RPCResult::Type::NUM, "daa", "Difficulty adjustment activation height."},
                        {RPCResult::Type::NUM, "magnetic_anomaly", "Magnetic Anomaly activation height."},
                        {RPCResult::Type::NUM, "graviton", "Graviton activation height."},
                        {RPCResult::Type::NUM, "phonon", "Phonon activation height."},
                        {RPCResult::Type::NUM, "axion", "Axion activation height."},
                        {RPCResult::Type::NUM, "upgrade8", "Upgrade8 activation height."},
                        {RPCResult::Type::NUM, "upgrade9", "Upgrade9 activation height."},
                        {RPCResult::Type::NUM, "upgrade10", "Upgrade10 activation height."},
                        {RPCResult::Type::NUM, "upgrade11", "Upgrade11 activation height."},
                        {RPCResult::Type::NUM, "upgrade12", "Upgrade12 activation height."},
                    }},
                    {RPCResult::Type::NUM, "segwit_height", "Configured SegWit activation height for current chain."},
                    {RPCResult::Type::BOOL, "segwit_disabled", "Whether SegWit is disabled (NEVER_ACTIVE_HEIGHT)."},
                    {RPCResult::Type::NUM, "taproot_start_time", "Configured Taproot deployment start time."},
                    {RPCResult::Type::BOOL, "taproot_disabled", "Whether Taproot deployment is disabled (NEVER_ACTIVE)."},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getcodequantuminfo", "")
                + HelpExampleRpc("getcodequantuminfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const CBlock& genesis_block = Params().GenesisBlock();

    UniValue result(UniValue::VOBJ);
    result.pushKV("enabled", true);
    result.pushKV("mode_wrapped_ecdsa", codequantum::MODE_V1_WRAPPED_ECDSA);

    UniValue algorithms(UniValue::VOBJ);
    algorithms.pushKV("wrapped_ecdsa_der", codequantum::ALGORITHM_V1_WRAPPED_ECDSA_DER);
    algorithms.pushKV("sha3_256t", codequantum::ALGORITHM_V1_SHA3_256T);
    algorithms.pushKV("mldsa_65", codequantum::ALGORITHM_V1_ML_DSA_65);
    result.pushKV("algorithms", std::move(algorithms));

    UniValue active_algorithms(UniValue::VARR);
    for (const uint8_t algorithm_id : codequantum::MODE_V1_ACTIVE_ALGORITHMS) {
        active_algorithms.push_back(algorithm_id);
    }
    result.pushKV("active_algorithms", std::move(active_algorithms));

    UniValue capabilities(UniValue::VOBJ);
    constexpr bool default_enable_code_quantum_signing{false};
    const bool wallet_code_quantum_signing_enabled = gArgs.GetBoolArg("-enablecodequantumsigning", default_enable_code_quantum_signing);
    const bool mldsa_65_native_verify_available = codequantum::MLDSA65NativeBackendAvailable();
    const bool mldsa_65_native_signing_available = codequantum::MLDSA65NativeBackendSigningAvailable();
    const bool code_quantum_signing_enabled = wallet_code_quantum_signing_enabled && mldsa_65_native_signing_available;
    const bool code_quantum_signing_verify_only = wallet_code_quantum_signing_enabled && !mldsa_65_native_signing_available;
    const bool code_quantum_signing_disabled = !wallet_code_quantum_signing_enabled;
    const char* mldsa_65_verify_state = mldsa_65_native_verify_available ? "available" : "unavailable";
    const char* code_quantum_signing_state = code_quantum_signing_enabled ? "enabled" : (code_quantum_signing_verify_only ? "verify_only" : "disabled");
    capabilities.pushKV("mldsa_65_runtime_enabled", codequantum::ML_DSA_65_RUNTIME_ENABLED);
    capabilities.pushKV("mldsa_65_native_verify_available", mldsa_65_native_verify_available);
    capabilities.pushKV("mldsa_65_verify_state", mldsa_65_verify_state);
    capabilities.pushKV("mldsa_65_native_signing_available", mldsa_65_native_signing_available);
    capabilities.pushKV("code_quantum_signing_disabled", code_quantum_signing_disabled);
    capabilities.pushKV("code_quantum_signing_verify_only", code_quantum_signing_verify_only);
    capabilities.pushKV("code_quantum_signing_enabled", code_quantum_signing_enabled);
    capabilities.pushKV("code_quantum_signing_state", code_quantum_signing_state);
    capabilities.pushKV("external_backend_scaffold_enabled", codequantum::MLDSA65ExternalBackendScaffoldEnabled());
    capabilities.pushKV("external_backend_header_detected", codequantum::MLDSA65ExternalBackendHeaderDetected());
#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_API)
    constexpr bool external_backend_verify_api_declared{true};
#else
    constexpr bool external_backend_verify_api_declared{false};
#endif
#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_VERIFY_LINK)
    constexpr bool external_backend_verify_linked{true};
#else
    constexpr bool external_backend_verify_linked{false};
#endif
    capabilities.pushKV("external_backend_verify_api_declared", external_backend_verify_api_declared);
    capabilities.pushKV("external_backend_verify_linked", external_backend_verify_linked);
    capabilities.pushKV("external_backend_bridge_ready", codequantum::MLDSA65ExternalBackendBridgeReady());
    result.pushKV("capabilities", std::move(capabilities));

    UniValue limits(UniValue::VOBJ);
    limits.pushKV("max_wrapped_sig_size", static_cast<uint64_t>(codequantum::MAX_WRAPPED_SIG_SIZE));
    limits.pushKV("max_envelope_size", static_cast<uint64_t>(codequantum::MAX_ENVELOPE_SIZE));
    result.pushKV("limits", std::move(limits));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("chain", Params().GetChainTypeString());

    UniValue genesis(UniValue::VOBJ);
    genesis.pushKV("hash", consensus.hashGenesisBlock.ToString());
    genesis.pushKV("merkle_root", genesis_block.hashMerkleRoot.ToString());
    genesis.pushKV("time", genesis_block.nTime);
    genesis.pushKV("nonce", genesis_block.nNonce);
    genesis.pushKV("bits", static_cast<uint64_t>(genesis_block.nBits));
    genesis.pushKV("version", genesis_block.nVersion);
    genesis.pushKV("reward_sats", static_cast<int64_t>(genesis_block.vtx[0]->vout[0].nValue));
    policy.pushKV("genesis", std::move(genesis));

    policy.pushKV("default_consensus_block_size", static_cast<uint64_t>(consensus.nDefaultConsensusBlockSize));
    policy.pushKV("pow_target_spacing", consensus.nPowTargetSpacing);
    policy.pushKV("pow_target_spacing_sha3", consensus.nPowTargetSpacingSHA3);
    policy.pushKV("sha3_height", consensus.SHA3Height);
    policy.pushKV("sha3_version_bit", consensus.SHA3VersionBit);
    policy.pushKV("hard_fork_height", consensus.fjarPolicyHardForkHeight);
    policy.pushKV("checkpoint_height", consensus.fjarPolicyCheckpointHeight);

    UniValue activation_matrix(UniValue::VOBJ);
    activation_matrix.pushKV("fjarcode", consensus.FJARCODEActivationHeight);
    activation_matrix.pushKV("uahf", consensus.uahfHeight);
    activation_matrix.pushKV("daa", consensus.daaHeight);
    activation_matrix.pushKV("magnetic_anomaly", consensus.magneticAnomalyHeight);
    activation_matrix.pushKV("graviton", consensus.gravitonHeight);
    activation_matrix.pushKV("phonon", consensus.phononHeight);
    activation_matrix.pushKV("axion", consensus.axionHeight);
    activation_matrix.pushKV("upgrade8", consensus.upgrade8Height);
    activation_matrix.pushKV("upgrade9", consensus.upgrade9Height);
    activation_matrix.pushKV("upgrade10", consensus.upgrade10Height);
    activation_matrix.pushKV("upgrade11", consensus.upgrade11Height);
    activation_matrix.pushKV("upgrade12", consensus.upgrade12Height);
    policy.pushKV("activation_matrix", std::move(activation_matrix));

    policy.pushKV("segwit_height", consensus.SegwitHeight);
    policy.pushKV("segwit_disabled", consensus.SegwitHeight == Consensus::NEVER_ACTIVE_HEIGHT);
    policy.pushKV("taproot_start_time", consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime);
    policy.pushKV("taproot_disabled", consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE);
    result.pushKV("policy", std::move(policy));

    return result;
},
    };
}

void RegisterNodeRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"control", &getmemoryinfo},
        {"control", &logging},
        {"util", &getcodequantuminfo},
        {"util", &getindexinfo},
        {"hidden", &setmocktime},
        {"hidden", &mockscheduler},
        {"hidden", &echo},
        {"hidden", &echojson},
        {"hidden", &echoipc},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
