// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/script_tests.json.h>
#include <test/data/bip341_wallet_vectors.json.h>

#include <common/system.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <crypto/sha3.h>
#include <key.h>
#include <rpc/util.h>
#include <script/code_quantum_mldsa.h>
#include <script/code_quantum_mldsa_backend_provider.h>
#include <script/code_quantum_mldsa_backend_native.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/script_flags.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>
#include <array>

#include <boost/test/unit_test.hpp>

#include <secp256k1.h>
#include <univalue.h>

// Uncomment if you want to output updated JSON tests.
// #define UPDATE_JSON_TESTS

using namespace util::hex_literals;

static const unsigned int gFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

unsigned int ParseScriptFlags(std::string strFlags);
std::string FormatScriptFlags(unsigned int flags);

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[]={
    {SCRIPT_ERR_OK, "OK"},
    {SCRIPT_ERR_UNKNOWN_ERROR, "UNKNOWN_ERROR"},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"},
    {SCRIPT_ERR_VERIFY, "VERIFY"},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"},
    {SCRIPT_ERR_WITNESS_PUBKEYTYPE, "WITNESS_PUBKEYTYPE"},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"},
    {SCRIPT_ERR_CODE_QUANTUM_NONCANONICAL_ENCODING, "CODE_QUANTUM_NONCANONICAL_ENCODING"},
    {SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_MODE, "CODE_QUANTUM_UNSUPPORTED_MODE"},
    {SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_ALGORITHM_ID, "CODE_QUANTUM_UNSUPPORTED_ALGORITHM_ID"},
    {SCRIPT_ERR_CODE_QUANTUM_MISSING_REQUIRED_SIG, "CODE_QUANTUM_MISSING_REQUIRED_SIG"},
    {SCRIPT_ERR_CODE_QUANTUM_ACTIVATION_STATE, "CODE_QUANTUM_ACTIVATION_STATE"},
};

static std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors)
        if (se.err == err)
            return se.name;
    BOOST_ERROR("Unknown scripterror enumeration value, update script_errors in script_tests.cpp.");
    return "";
}

static ScriptError_t ParseScriptError(const std::string& name)
{
    for (const auto& se : script_errors)
        if (se.name == name)
            return se.err;
    BOOST_ERROR("Unknown scripterror \"" << name << "\" in test description");
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

static int g_mldsa_backend_hook_calls = 0;

static bool CountingMLDSABackendHook(const std::vector<unsigned char>&,
                                     const std::vector<unsigned char>&,
                                     const CScript&)
{
    ++g_mldsa_backend_hook_calls;
    return false;
}

#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
static int g_mldsa_external_bridge_calls = 0;
static int g_mldsa_external_request_observer_calls = 0;
static uint8_t g_mldsa_external_result_code_to_return = codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_UNAVAILABLE;
static std::string g_mldsa_external_callback_trace;
static uint32_t g_mldsa_external_observed_request_version = 0;
static uint32_t g_mldsa_external_observed_capability_flags = 0;
static uint32_t g_mldsa_external_observed_capability_profile_id = 0;
static std::array<unsigned char, 8> g_mldsa_external_observed_request_magic{};
static uint32_t g_mldsa_external_observed_request_shape_hash = 0;
static std::array<unsigned char, 16> g_mldsa_external_observed_interface_id{};
static const std::vector<unsigned char>* g_mldsa_external_observed_wrapped_sig_ptr = nullptr;
static const std::vector<unsigned char>* g_mldsa_external_observed_pubkey_ptr = nullptr;
static const CScript* g_mldsa_external_observed_script_code_ptr = nullptr;
static size_t g_mldsa_external_observed_der_sig_size = 0;
static size_t g_mldsa_external_observed_pubkey_payload_size = 0;
static unsigned char g_mldsa_external_observed_sighash_type = 0;
static bool g_mldsa_external_observed_pubkey_is_compressed = false;
static std::array<unsigned char, 13> g_mldsa_external_observed_prehash_domain_tag{};
static std::array<unsigned char, 32> g_mldsa_external_observed_prehashed_sighash32{};
static std::array<unsigned char, 32> g_mldsa_external_observed_request_content_digest32{};
static std::array<unsigned char, 32> g_mldsa_external_observed_request_content_digest32_recomputed{};

static codequantum::MLDSA65BackendAdapterResult ExternalBridgeVerified(const std::vector<unsigned char>&,
                                                                        const std::vector<unsigned char>&,
                                                                        const CScript&)
{
    ++g_mldsa_external_bridge_calls;
    return codequantum::MLDSA65BackendAdapterResult::VERIFIED;
}

static codequantum::MLDSA65BackendAdapterResult ExternalBridgeVerifiedWithTrace(const std::vector<unsigned char>&,
                                                                                 const std::vector<unsigned char>&,
                                                                                 const CScript&)
{
    ++g_mldsa_external_bridge_calls;
    g_mldsa_external_callback_trace += "V";
    return codequantum::MLDSA65BackendAdapterResult::VERIFIED;
}

static void ObserveExternalRequest(const codequantum::MLDSA65ExternalBackendRequest& request)
{
    ++g_mldsa_external_request_observer_calls;
    g_mldsa_external_observed_request_version = request.request_version;
    g_mldsa_external_observed_capability_flags = request.capability_flags;
    g_mldsa_external_observed_capability_profile_id = request.capability_profile_id;
    g_mldsa_external_observed_request_magic = request.request_magic;
    g_mldsa_external_observed_request_shape_hash = request.request_shape_hash;
    g_mldsa_external_observed_interface_id = request.external_backend_interface_id;
    g_mldsa_external_observed_wrapped_sig_ptr = request.wrapped_sig;
    g_mldsa_external_observed_pubkey_ptr = request.pubkey;
    g_mldsa_external_observed_script_code_ptr = request.script_code;
    g_mldsa_external_observed_der_sig_size = request.der_sig_size;
    g_mldsa_external_observed_pubkey_payload_size = request.pubkey_payload_size;
    g_mldsa_external_observed_sighash_type = request.sighash_type;
    g_mldsa_external_observed_pubkey_is_compressed = request.pubkey_is_compressed;
    g_mldsa_external_observed_prehash_domain_tag = request.prehash_domain_tag;
    g_mldsa_external_observed_prehashed_sighash32 = request.prehashed_sighash32;
    g_mldsa_external_observed_request_content_digest32 = request.request_content_digest32;
    g_mldsa_external_observed_request_content_digest32_recomputed = codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(request);
}

static uint8_t ExternalBridgeResultCodeFromRequest(const codequantum::MLDSA65ExternalBackendRequest&)
{
    return g_mldsa_external_result_code_to_return;
}

static uint8_t ExternalBridgeResultCodeFromRequestWithTrace(const codequantum::MLDSA65ExternalBackendRequest&)
{
    g_mldsa_external_callback_trace += "R";
    return g_mldsa_external_result_code_to_return;
}

static void ObserveExternalRequestWithTrace(const codequantum::MLDSA65ExternalBackendRequest& request)
{
    ObserveExternalRequest(request);
    g_mldsa_external_callback_trace += "O";
}

static void ObserveExternalRequestMutateDigest(const codequantum::MLDSA65ExternalBackendRequest& request)
{
    ObserveExternalRequest(request);
    g_mldsa_external_callback_trace += "M";
    const_cast<codequantum::MLDSA65ExternalBackendRequest&>(request).request_shape_hash ^= 1U;
}

static std::array<unsigned char, 32> ComputeExpectedExternalPrehashedSighash(const CScript& scriptCode,
                                                                              unsigned char sighash_type)
{
    std::array<unsigned char, 32> digest{};
    CSHA256 hasher;
    hasher.Write(codequantum::MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG.data(), codequantum::MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG.size());
    if (!scriptCode.empty()) {
        hasher.Write(scriptCode.data(), scriptCode.size());
    }
    hasher.Write(&sighash_type, 1);
    hasher.Finalize(digest.data());
    return digest;
}
#endif

#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
static int g_mldsa_native_provider_calls = 0;
static int g_mldsa_native_default_factory_calls = 0;
static int g_mldsa_native_signer_calls = 0;
static std::array<unsigned char, 32> g_mldsa_native_last_sign_prehash{};
static bool g_mldsa_native_last_sign_prehash_set = false;
#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
static int g_mldsa_native_external_bridge_verify_calls = 0;
#endif

static codequantum::MLDSA65BackendAdapterResult NativeProviderVerified(const std::vector<unsigned char>&,
                                                                       const std::vector<unsigned char>&,
                                                                       const CScript&)
{
    ++g_mldsa_native_provider_calls;
    return codequantum::MLDSA65BackendAdapterResult::VERIFIED;
}

static codequantum::MLDSA65BackendAdapterResult NativeProviderUnavailable(const std::vector<unsigned char>&,
                                                                          const std::vector<unsigned char>&,
                                                                          const CScript&)
{
    ++g_mldsa_native_provider_calls;
    return codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE;
}

static codequantum::MLDSA65BackendAdapterResult NativeProviderRejected(const std::vector<unsigned char>&,
                                                                       const std::vector<unsigned char>&,
                                                                       const CScript&)
{
    ++g_mldsa_native_provider_calls;
    return codequantum::MLDSA65BackendAdapterResult::REJECTED;
}

static codequantum::MLDSA65BackendAdapterResult NativeProviderInvalidEnum(const std::vector<unsigned char>&,
                                                                          const std::vector<unsigned char>&,
                                                                          const CScript&)
{
    ++g_mldsa_native_provider_calls;
    return static_cast<codequantum::MLDSA65BackendAdapterResult>(255);
}

static codequantum::MLDSA65BackendAdapterResult NativeProviderImplementationProbe(const std::vector<unsigned char>& wrapped_sig,
                                                                                  const std::vector<unsigned char>&,
                                                                                  const CScript&)
{
    ++g_mldsa_native_provider_calls;
    if (!wrapped_sig.empty() && wrapped_sig.back() == static_cast<unsigned char>(SIGHASH_NONE)) {
        return codequantum::MLDSA65BackendAdapterResult::VERIFIED;
    }
    return codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE;
}

static bool NativeProviderAvailableTrue()
{
    return true;
}

static bool NativeProviderAvailableFalse()
{
    return false;
}

static codequantum::MLDSA65NativeBackendBinding NativeDefaultBindingFactoryVerified()
{
    ++g_mldsa_native_default_factory_calls;
    return {nullptr, NativeProviderVerified};
}

static codequantum::MLDSA65NativeBackendBinding NativeDefaultBindingFactoryAvailabilityOnly()
{
    ++g_mldsa_native_default_factory_calls;
    return {NativeProviderAvailableTrue, nullptr};
}

static codequantum::MLDSA65NativeBackendSignResult NativeSignerDeterministic(const std::vector<unsigned char>&,
                                                                              const std::array<unsigned char, 32>& prehashed_sighash32,
                                                                              unsigned char sighash_type,
                                                                              std::vector<unsigned char>& out_wrapped_sig)
{
    ++g_mldsa_native_signer_calls;
    g_mldsa_native_last_sign_prehash = prehashed_sighash32;
    g_mldsa_native_last_sign_prehash_set = true;
    out_wrapped_sig = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        sighash_type,
    };
    return codequantum::MLDSA65NativeBackendSignResult::SIGNED;
}

static codequantum::MLDSA65NativeBackendSignResult NativeSignerMalformed(const std::vector<unsigned char>&,
                                                                          const std::array<unsigned char, 32>& prehashed_sighash32,
                                                                          unsigned char,
                                                                          std::vector<unsigned char>& out_wrapped_sig)
{
    ++g_mldsa_native_signer_calls;
    g_mldsa_native_last_sign_prehash = prehashed_sighash32;
    g_mldsa_native_last_sign_prehash_set = true;
    out_wrapped_sig = {0x01};
    return codequantum::MLDSA65NativeBackendSignResult::SIGNED;
}

static codequantum::MLDSA65NativeBackendSignResult NativeSignerInvalidEnum(const std::vector<unsigned char>&,
                                                                            const std::array<unsigned char, 32>& prehashed_sighash32,
                                                                            unsigned char,
                                                                            std::vector<unsigned char>& out_wrapped_sig)
{
    ++g_mldsa_native_signer_calls;
    g_mldsa_native_last_sign_prehash = prehashed_sighash32;
    g_mldsa_native_last_sign_prehash_set = true;
    out_wrapped_sig.clear();
    return static_cast<codequantum::MLDSA65NativeBackendSignResult>(255);
}

static std::array<unsigned char, 32> ComputeExpectedNativeBuiltinPrehash(const CScript& script_code,
                                                                          unsigned char sighash_type)
{
    std::array<unsigned char, 32> digest{};
    CSHA256 hasher;
    hasher.Write(codequantum::MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG.data(), codequantum::MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG.size());
    if (!script_code.empty()) {
        hasher.Write(script_code.data(), script_code.size());
    }
    hasher.Write(&sighash_type, 1);
    hasher.Finalize(digest.data());
    return digest;
}

#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
static bool NativeProviderExternalBridgeAvailable()
{
    return codequantum::MLDSA65ExternalBackendBridgeReady();
}

static codequantum::MLDSA65BackendAdapterResult NativeProviderExternalBridgeVerify(const std::vector<unsigned char>& wrapped_sig,
                                                                                   const std::vector<unsigned char>& vchPubKey,
                                                                                   const CScript& scriptCode)
{
    ++g_mldsa_native_external_bridge_verify_calls;
    return codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig, vchPubKey, scriptCode);
}
#endif
#endif

struct ScriptTest : BasicTestingSetup {
void DoTest(const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& scriptWitness, uint32_t flags, const std::string& message, int scriptError, CAmount nValue = 0)
{
    bool expect = (scriptError == SCRIPT_ERR_OK);
    if (flags & SCRIPT_VERIFY_CLEANSTACK) {
        flags |= SCRIPT_VERIFY_P2SH;
        flags |= SCRIPT_VERIFY_WITNESS;
    }
    ScriptError err;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, nValue)};
    CMutableTransaction tx = BuildSpendingTransaction(scriptSig, scriptWitness, txCredit);
    BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message);
    BOOST_CHECK_MESSAGE(err == scriptError, FormatScriptError(err) + " where " + FormatScriptError((ScriptError_t)scriptError) + " expected: " + message);

    // Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
    for (int i = 0; i < 16; ++i) {
        uint32_t extra_flags(m_rng.randbits(16));
        uint32_t combined_flags{expect ? (flags & ~extra_flags) : (flags | extra_flags)};
        // Weed out some invalid flag combinations.
        if (combined_flags & SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) continue;
        if (combined_flags & SCRIPT_VERIFY_WITNESS && ~combined_flags & SCRIPT_VERIFY_P2SH) continue;
        BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, combined_flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message + strprintf(" (with flags %x)", combined_flags));
    }
}
}; // struct ScriptTest

void static NegateSignatureS(std::vector<unsigned char>& vchSig) {
    // Parse the signature.
    std::vector<unsigned char> r, s;
    r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
    s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);

    while (s.size() < 33) {
        s.insert(s.begin(), 0x00);
    }
    assert(s[0] == 0);
    // Perform mod-n negation of s by (ab)using libsecp256k1
    // (note that this function is meant to be used for negating secret keys,
    //  but it works for any non-zero scalar modulo the group order, i.e. also for s)
    int ret = secp256k1_ec_seckey_negate(secp256k1_context_static, s.data() + 1);
    assert(ret);

    if (s[1] < 0x80) {
        s.erase(s.begin());
    }

    // Reconstruct the signature.
    vchSig.clear();
    vchSig.push_back(0x30);
    vchSig.push_back(4 + r.size() + s.size());
    vchSig.push_back(0x02);
    vchSig.push_back(r.size());
    vchSig.insert(vchSig.end(), r.begin(), r.end());
    vchSig.push_back(0x02);
    vchSig.push_back(s.size());
    vchSig.insert(vchSig.end(), s.begin(), s.end());
}

namespace
{
const unsigned char vchKey0[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const unsigned char vchKey1[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0};
const unsigned char vchKey2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char*>(pubkey0H.data()) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};

enum class WitnessMode {
    NONE,
    PKH,
    SH
};

class TestBuilder
{
private:
    //! Actually executed script
    CScript script;
    //! The P2SH redeemscript
    CScript redeemscript;
    //! The Witness embedded script
    CScript witscript;
    CScriptWitness scriptWitness;
    CTransactionRef creditTx;
    CMutableTransaction spendTx;
    bool havePush{false};
    std::vector<unsigned char> push;
    std::string comment;
    uint32_t flags;
    int scriptError{SCRIPT_ERR_OK};
    CAmount nValue;

    void DoPush()
    {
        if (havePush) {
            spendTx.vin[0].scriptSig << push;
            havePush = false;
        }
    }

    void DoPush(const std::vector<unsigned char>& data)
    {
        DoPush();
        push = data;
        havePush = true;
    }

public:
    TestBuilder(const CScript& script_, const std::string& comment_, uint32_t flags_, bool P2SH = false, WitnessMode wm = WitnessMode::NONE, int witnessversion = 0, CAmount nValue_ = 0) : script(script_), comment(comment_), flags(flags_), nValue(nValue_)
    {
        CScript scriptPubKey = script;
        if (wm == WitnessMode::PKH) {
            uint160 hash;
            CHash160().Write(std::span{script}.subspan(1)).Finalize(hash);
            script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_CHECKSIG;
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        } else if (wm == WitnessMode::SH) {
            witscript = scriptPubKey;
            uint256 hash;
            CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        }
        if (P2SH) {
            redeemscript = scriptPubKey;
            scriptPubKey = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeemscript)) << OP_EQUAL;
        }
        creditTx = MakeTransactionRef(BuildCreditingTransaction(scriptPubKey, nValue));
        spendTx = BuildSpendingTransaction(CScript(), CScriptWitness(), *creditTx);
    }

    TestBuilder& ScriptError(ScriptError_t err)
    {
        scriptError = err;
        return *this;
    }

    TestBuilder& Opcode(const opcodetype& _op)
    {
        DoPush();
        spendTx.vin[0].scriptSig << _op;
        return *this;
    }

    TestBuilder& Num(int num)
    {
        DoPush();
        spendTx.vin[0].scriptSig << num;
        return *this;
    }

    TestBuilder& Push(const std::string& hex)
    {
        DoPush(ParseHex(hex));
        return *this;
    }

    TestBuilder& Push(const CScript& _script)
    {
        DoPush(std::vector<unsigned char>(_script.begin(), _script.end()));
        return *this;
    }

    TestBuilder& PushSig(const CKey& key, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::BASE, CAmount amount = 0)
    {
        uint256 hash = SignatureHash(script, spendTx, 0, nHashType, amount, sigversion);
        std::vector<unsigned char> vchSig, r, s;
        uint32_t iter = 0;
        do {
            key.Sign(hash, vchSig, false, iter++);
            if ((lenS == 33) != (vchSig[5 + vchSig[3]] == 33)) {
                NegateSignatureS(vchSig);
            }
            r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
            s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);
        } while (lenR != r.size() || lenS != s.size());
        vchSig.push_back(static_cast<unsigned char>(nHashType));
        DoPush(vchSig);
        return *this;
    }

    TestBuilder& PushWitSig(const CKey& key, CAmount amount = -1, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::WITNESS_V0)
    {
        if (amount == -1)
            amount = nValue;
        return PushSig(key, nHashType, lenR, lenS, sigversion, amount).AsWit();
    }

    TestBuilder& Push(const CPubKey& pubkey)
    {
        DoPush(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
        return *this;
    }

    TestBuilder& PushRedeem()
    {
        DoPush(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        return *this;
    }

    TestBuilder& PushWitRedeem()
    {
        DoPush(std::vector<unsigned char>(witscript.begin(), witscript.end()));
        return AsWit();
    }

    TestBuilder& EditPush(unsigned int pos, const std::string& hexin, const std::string& hexout)
    {
        assert(havePush);
        std::vector<unsigned char> datain = ParseHex(hexin);
        std::vector<unsigned char> dataout = ParseHex(hexout);
        assert(pos + datain.size() <= push.size());
        BOOST_CHECK_MESSAGE(std::vector<unsigned char>(push.begin() + pos, push.begin() + pos + datain.size()) == datain, comment);
        push.erase(push.begin() + pos, push.begin() + pos + datain.size());
        push.insert(push.begin() + pos, dataout.begin(), dataout.end());
        return *this;
    }

    TestBuilder& DamagePush(unsigned int pos)
    {
        assert(havePush);
        assert(pos < push.size());
        push[pos] ^= 1;
        return *this;
    }

    TestBuilder& Test(ScriptTest& test)
    {
        TestBuilder copy = *this; // Make a copy so we can rollback the push.
        DoPush();
        test.DoTest(creditTx->vout[0].scriptPubKey, spendTx.vin[0].scriptSig, scriptWitness, flags, comment, scriptError, nValue);
        *this = copy;
        return *this;
    }

    TestBuilder& AsWit()
    {
        assert(havePush);
        scriptWitness.stack.push_back(push);
        havePush = false;
        return *this;
    }

    UniValue GetJSON()
    {
        DoPush();
        UniValue array(UniValue::VARR);
        if (!scriptWitness.stack.empty()) {
            UniValue wit(UniValue::VARR);
            for (unsigned i = 0; i < scriptWitness.stack.size(); i++) {
                wit.push_back(HexStr(scriptWitness.stack[i]));
            }
            wit.push_back(ValueFromAmount(nValue));
            array.push_back(std::move(wit));
        }
        array.push_back(FormatScript(spendTx.vin[0].scriptSig));
        array.push_back(FormatScript(creditTx->vout[0].scriptPubKey));
        array.push_back(FormatScriptFlags(flags));
        array.push_back(FormatScriptError((ScriptError_t)scriptError));
        array.push_back(comment);
        return array;
    }

    std::string GetComment() const
    {
        return comment;
    }
};

std::string JSONPrettyPrint(const UniValue& univalue)
{
    std::string ret = univalue.write(4);
    // Workaround for libunivalue pretty printer, which puts a space between commas and newlines
    size_t pos = 0;
    while ((pos = ret.find(" \n", pos)) != std::string::npos) {
        ret.replace(pos, 2, "\n");
        pos++;
    }
    return ret;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, ScriptTest)

BOOST_AUTO_TEST_CASE(script_build)
{
    const KeyData keys;

    std::vector<TestBuilder> tests;

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK", 0
                               ).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK, bad sig", 0
                               ).PushSig(keys.key0).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH", 0
                               ).PushSig(keys.key1).Push(keys.pubkey1C));
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey2C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH, bad pubkey", 0
                               ).PushSig(keys.key2).Push(keys.pubkey2C).DamagePush(5).ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay marked with normal hashtype", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY).EditPush(70, "81", "01").ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK), bad redeemscript", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem().DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey0.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).Push(keys.pubkey0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig but no VERIFY_P2SH", 0, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem().ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3, 2 sigs", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3)", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key2).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3), 1 sig", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).Num(0).PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, without DERSIG", 0
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, without DERSIG", 0
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, without DERSIG", 0
                               ).Num(1).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, without DERSIG", 0
                               ).Num(1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, without DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S but no LOW_S", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S", SCRIPT_VERIFY_LOW_S
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33).ScriptError(SCRIPT_ERR_SIG_HIGH_S));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey and no STRICTENC", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0H) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the first 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig and nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP but no SIGPUSHONLY", 0
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP).ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no P2SH or SIGPUSHONLY", 0, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with non-push scriptSig but with P2SH validation", 0
                               ).PushSig(keys.key2).Opcode(OP_NOP8));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no SIGPUSHONLY", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but not P2SH", SCRIPT_VERIFY_SIGPUSHONLY, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0).ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem().ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with future witness version", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH |
                                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, false, WitnessMode::PKH, 1
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0);
        uint256 hash;
        CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
        std::vector<unsigned char> hashBytes = ToByteVector(hash);
        hashBytes.pop_back();
        tests.push_back(TestBuilder(CScript() << OP_0 << hashBytes,
                                    "P2WPKH with wrong witness program length", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false
                                   ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2WSH with empty witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(witscript,
                                    "P2WSH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                                   ).PushWitSig(keys.key0).Push(witscript).DamagePush(0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with non-empty scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Num(11).ScriptError(SCRIPT_ERR_WITNESS_MALLEATED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "P2SH(P2WPKH) with superfluous push in scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().Num(11).PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_MALLEATED_P2SH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH
                               ).PushSig(keys.key0).Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_UNEXPECTED));

    // Compressed keys should pass SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2WSH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2WPKH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2SH(P2WPKH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit().PushRedeem());

    // Testing uncompressed key in witness with SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    // P2WSH 1-of-2 multisig with compressed keys
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());

    // P2WSH 1-of-2 multisig with first key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    // P2WSH 1-of-2 multisig with second key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    std::set<std::string> tests_set;

    {
        UniValue json_tests = read_json(json_tests::script_tests);

        for (unsigned int idx = 0; idx < json_tests.size(); idx++) {
            const UniValue& tv = json_tests[idx];
            tests_set.insert(JSONPrettyPrint(tv.get_array()));
        }
    }

#ifdef UPDATE_JSON_TESTS
    std::string strGen;
#endif
    for (TestBuilder& test : tests) {
        test.Test(*this);
        std::string str = JSONPrettyPrint(test.GetJSON());
#ifdef UPDATE_JSON_TESTS
        strGen += str + ",\n";
#else
        if (tests_set.count(str) == 0) {
            BOOST_CHECK_MESSAGE(false, "Missing auto script_valid test: " + test.GetComment());
        }
#endif
    }

#ifdef UPDATE_JSON_TESTS
    FILE* file = fsbridge::fopen("script_tests.json.gen", "w");
    fputs(strGen.c_str(), file);
    fclose(file);
#endif
}

BOOST_AUTO_TEST_CASE(script_json_test)
{
    // Read tests from test/data/script_tests.json
    // Format is an array of arrays
    // Inner arrays are [ ["wit"..., nValue]?, "scriptSig", "scriptPubKey", "flags", "expected_scripterror" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    // If a witness is given, then the last value in the array should be the
    // amount (nValue) to use in the crediting tx
    UniValue tests = read_json(json_tests::script_tests);

    const KeyData keys;
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        CScriptWitness witness;
        TaprootBuilder taprootBuilder;
        CAmount nValue = 0;
        unsigned int pos = 0;
        if (test.size() > 0 && test[pos].isArray()) {
            unsigned int i=0;
            for (i = 0; i < test[pos].size()-1; i++) {
                auto element = test[pos][i].get_str();
                // We use #SCRIPT# to flag a non-hex script that we can read using ParseScript
                // Taproot script must be third from the last element in witness stack
                static const std::string SCRIPT_FLAG{"#SCRIPT#"};
                if (element.starts_with(SCRIPT_FLAG)) {
                    CScript script = ParseScript(element.substr(SCRIPT_FLAG.size()));
                    witness.stack.push_back(ToByteVector(script));
                } else if (element == "#CONTROLBLOCK#") {
                    // Taproot script control block - second from the last element in witness stack
                    // If #CONTROLBLOCK# we auto-generate the control block
                    taprootBuilder.Add(/*depth=*/0, witness.stack.back(), TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
                    taprootBuilder.Finalize(XOnlyPubKey(keys.key0.GetPubKey()));
                    auto controlblocks = taprootBuilder.GetSpendData().scripts[{witness.stack.back(), TAPROOT_LEAF_TAPSCRIPT}];
                    witness.stack.push_back(*(controlblocks.begin()));
                } else {
                    const auto witness_value{TryParseHex<unsigned char>(element)};
                    if (!witness_value.has_value()) {
                        BOOST_ERROR("Bad witness in test: " << strTest << " witness is not hex: " << element);
                    }
                    witness.stack.push_back(witness_value.value());
                }
            }
            nValue = AmountFromValue(test[pos][i]);
            pos++;
        }
        if (test.size() < 4 + pos) // Allow size > 3; extra stuff ignored (useful for comments)
        {
            if (test.size() != 1) {
                BOOST_ERROR("Bad test: " << strTest);
            }
            continue;
        }
        std::string scriptSigString = test[pos++].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        std::string scriptPubKeyString = test[pos++].get_str();
        CScript scriptPubKey;
        // If requested, auto-generate the taproot output
        if (scriptPubKeyString == "0x51 0x20 #TAPROOTOUTPUT#") {
            BOOST_CHECK_MESSAGE(taprootBuilder.IsComplete(), "Failed to autogenerate Tapscript output key");
            scriptPubKey = CScript() << OP_1 << ToByteVector(taprootBuilder.GetOutput());
        } else {
            scriptPubKey = ParseScript(scriptPubKeyString);
        }
        unsigned int scriptflags = ParseScriptFlags(test[pos++].get_str());
        int scriptError = ParseScriptError(test[pos++].get_str());

        DoTest(scriptPubKey, scriptSig, witness, scriptflags, strTest, scriptError, nValue);
    }
}

BOOST_AUTO_TEST_CASE(script_PushData)
{
    // Check that PUSHDATA1, PUSHDATA2, and PUSHDATA4 create the same value on
    // the stack as the 1-75 opcodes do.
    static const unsigned char direct[] = { 1, 0x5a };
    static const unsigned char pushdata1[] = { OP_PUSHDATA1, 1, 0x5a };
    static const unsigned char pushdata2[] = { OP_PUSHDATA2, 1, 0, 0x5a };
    static const unsigned char pushdata4[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x5a };

    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack;
    BOOST_CHECK(EvalScript(directStack, CScript(direct, direct + sizeof(direct)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata1Stack;
    BOOST_CHECK(EvalScript(pushdata1Stack, CScript(pushdata1, pushdata1 + sizeof(pushdata1)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata1Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata2Stack;
    BOOST_CHECK(EvalScript(pushdata2Stack, CScript(pushdata2, pushdata2 + sizeof(pushdata2)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata2Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata4Stack;
    BOOST_CHECK(EvalScript(pushdata4Stack, CScript(pushdata4, pushdata4 + sizeof(pushdata4)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata4Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    const std::vector<unsigned char> pushdata1_trunc{OP_PUSHDATA1, 1};
    const std::vector<unsigned char> pushdata2_trunc{OP_PUSHDATA2, 1, 0};
    const std::vector<unsigned char> pushdata4_trunc{OP_PUSHDATA4, 1, 0, 0, 0};

    std::vector<std::vector<unsigned char>> stack_ignore;
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata1_trunc.begin(), pushdata1_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata2_trunc.begin(), pushdata2_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata4_trunc.begin(), pushdata4_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(script_cltv_truncated)
{
    const auto script_cltv_trunc = CScript() << OP_CHECKLOCKTIMEVERIFY;

    std::vector<std::vector<unsigned char>> stack_ignore;
    ScriptError err;
    BOOST_CHECK(!EvalScript(stack_ignore, script_cltv_trunc, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

static CScript
sign_multisig(const CScript& scriptPubKey, const std::vector<CKey>& keys, const CTransaction& transaction)
{
    uint256 hash = SignatureHash(scriptPubKey, transaction, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    CScript result;
    //
    // NOTE: CHECKMULTISIG has an unfortunate bug; it requires
    // one extra item on the stack, before the signatures.
    // Putting OP_0 on the stack is the workaround;
    // fixing the bug would mean splitting the block chain (old
    // clients would not accept new CHECKMULTISIG transactions,
    // and vice-versa)
    //
    result << OP_0;
    for (const CKey &key : keys)
    {
        std::vector<unsigned char> vchSig;
        BOOST_CHECK(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        result << vchSig;
    }
    return result;
}
static CScript
sign_multisig(const CScript& scriptPubKey, const CKey& key, const CTransaction& transaction)
{
    std::vector<CKey> keys;
    keys.push_back(key);
    return sign_multisig(scriptPubKey, keys, transaction);
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG12)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();

    CScript scriptPubKey12;
    scriptPubKey12 << OP_1 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    const CTransaction txFrom12{BuildCreditingTransaction(scriptPubKey12)};
    CMutableTransaction txTo12 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom12);

    CScript goodsig1 = sign_multisig(scriptPubKey12, key1, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    txTo12.vout[0].nValue = 2;
    BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    CScript goodsig2 = sign_multisig(scriptPubKey12, key2, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    CScript badsig1 = sign_multisig(scriptPubKey12, key3, CTransaction(txTo12));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG23)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();
    CKey key4 = GenerateRandomKey(/*compressed=*/false);

    CScript scriptPubKey23;
    scriptPubKey23 << OP_2 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << ToByteVector(key3.GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    const CTransaction txFrom23{BuildCreditingTransaction(scriptPubKey23)};
    CMutableTransaction txTo23 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom23);

    std::vector<CKey> keys;
    keys.push_back(key1); keys.push_back(key2);
    CScript goodsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key3);
    CScript goodsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key3);
    CScript goodsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key2); // Can't reuse sig
    CScript badsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key1); // sigs must be in correct order
    CScript badsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key3); keys.push_back(key2); // sigs must be in correct order
    CScript badsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key4); keys.push_back(key2); // sigs must match pubkeys
    CScript badsig4 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig4, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key4); // sigs must match pubkeys
    CScript badsig5 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig5, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear(); // Must have signatures
    CScript badsig6 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig6, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_STACK_OPERATION, ScriptErrorString(err));
}

/** Return the TxoutType of a script without exposing Solver details. */
static TxoutType GetTxoutType(const CScript& output_script)
{
    std::vector<std::vector<uint8_t>> unused;
    return Solver(output_script, unused);
}

#define CHECK_SCRIPT_STATIC_SIZE(script, expected_size)                   \
    do {                                                                  \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));              \
        BOOST_CHECK_EQUAL((script).capacity(), CScriptBase::STATIC_SIZE); \
        BOOST_CHECK_EQUAL((script).allocated_memory(), 0);                \
    } while (0)

#define CHECK_SCRIPT_DYNAMIC_SIZE(script, expected_size, expected_extra)                 \
    do {                                                                 \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));             \
        BOOST_CHECK_EQUAL((script).capacity(), (expected_extra));         \
        BOOST_CHECK_EQUAL((script).allocated_memory(), (expected_extra)); \
    } while (0)

BOOST_AUTO_TEST_CASE(script_size_and_capacity_test)
{
    BOOST_CHECK_EQUAL(sizeof(CompressedScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CScriptBase), 40);
    BOOST_CHECK_NE(sizeof(CScriptBase), sizeof(prevector<CScriptBase::STATIC_SIZE + 1, uint8_t>)); // CScriptBase size should be set to avoid wasting space in padding
    BOOST_CHECK_EQUAL(sizeof(CScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CTxOut), 48);

    CKey dummy_key;
    dummy_key.MakeNewKey(/*fCompressed=*/true);
    const CPubKey dummy_pubkey{dummy_key.GetPubKey()};

    // Small OP_RETURN has direct allocation
    {
        const auto script{CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xaa)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::NULL_DATA);
        CHECK_SCRIPT_STATIC_SIZE(script, 12);
    }

    // P2WPKH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0KeyHash{PKHash{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V0_KEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 22);
    }

    // P2SH has direct allocation
    {
        const auto script{GetScriptForDestination(ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 23);
    }

    // P2PKH has direct allocation
    {
        const auto script{GetScriptForDestination(PKHash{dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEYHASH);
        CHECK_SCRIPT_STATIC_SIZE(script, 25);
    }

    // P2WSH has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV0ScriptHash{CScript{} << OP_TRUE})};
        BOOST_CHECK(script.IsPayToWitnessScriptHash());
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // P2TR has direct allocation
    {
        const auto script{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{dummy_pubkey}})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::WITNESS_V1_TAPROOT);
        CHECK_SCRIPT_STATIC_SIZE(script, 34);
    }

    // Compressed P2PK has direct allocation
    {
        const auto script{GetScriptForRawPubKey(dummy_pubkey)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEY);
        CHECK_SCRIPT_STATIC_SIZE(script, 35);
    }

    // Uncompressed P2PK needs extra allocation
    {
        CKey uncompressed_key;
        uncompressed_key.MakeNewKey(/*fCompressed=*/false);
        const CPubKey uncompressed_pubkey{uncompressed_key.GetPubKey()};

        const auto script{GetScriptForRawPubKey(uncompressed_pubkey)};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::PUBKEY);
        CHECK_SCRIPT_DYNAMIC_SIZE(script, 67, 67);
    }

    // Bare multisig needs extra allocation
    {
        const auto script{GetScriptForMultisig(1, std::vector{2, dummy_pubkey})};
        BOOST_CHECK_EQUAL(GetTxoutType(script), TxoutType::MULTISIG);
        CHECK_SCRIPT_DYNAMIC_SIZE(script, 71, 103);
    }
}

/* Wrapper around ProduceSignature to combine two scriptsigs */
SignatureData CombineSignatures(const CTxOut& txout, const CMutableTransaction& tx, const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    SignatureData data;
    data.MergeSignatureData(scriptSig1);
    data.MergeSignatureData(scriptSig2);
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(tx, 0, txout.nValue, SIGHASH_DEFAULT), txout.scriptPubKey, data);
    return data;
}

BOOST_AUTO_TEST_CASE(script_combineSigs)
{
    // Test the ProduceSignature's ability to combine signatures function
    FillableSigningProvider keystore;
    std::vector<CKey> keys;
    std::vector<CPubKey> pubkeys;
    for (int i = 0; i < 3; i++)
    {
        CKey key = GenerateRandomKey(/*compressed=*/i%2 == 1);
        keys.push_back(key);
        pubkeys.push_back(key.GetPubKey());
        BOOST_CHECK(keystore.AddKey(key));
    }

    CMutableTransaction txFrom = BuildCreditingTransaction(GetScriptForDestination(PKHash(keys[0].GetPubKey())));
    CMutableTransaction txTo = BuildSpendingTransaction(CScript(), CScriptWitness(), CTransaction(txFrom));
    CScript& scriptPubKey = txFrom.vout[0].scriptPubKey;
    SignatureData scriptSig;

    SignatureData empty;
    SignatureData combined = CombineSignatures(txFrom.vout[0], txTo, empty, empty);
    BOOST_CHECK(combined.scriptSig.empty());

    // Single signature case:
    SignatureData dummy;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy)); // changes scriptSig
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    SignatureData scriptSigCopy = scriptSig;
    // Signing again will give a different, valid signature:
    SignatureData dummy_b;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_b));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // P2SH, single-signature case:
    CScript pkSingle; pkSingle << ToByteVector(keys[0].GetPubKey()) << OP_CHECKSIG;
    BOOST_CHECK(keystore.AddCScript(pkSingle));
    scriptPubKey = GetScriptForDestination(ScriptHash(pkSingle));
    SignatureData dummy_c;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_c));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    scriptSigCopy = scriptSig;
    SignatureData dummy_d;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_d));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // Hardest case:  Multisig 2-of-3
    scriptPubKey = GetScriptForMultisig(2, pubkeys);
    BOOST_CHECK(keystore.AddCScript(scriptPubKey));
    SignatureData dummy_e;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_e));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);

    // A couple of partially-signed versions:
    std::vector<unsigned char> sig1;
    uint256 hash1 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keys[0].Sign(hash1, sig1));
    sig1.push_back(SIGHASH_ALL);
    std::vector<unsigned char> sig2;
    uint256 hash2 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_NONE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[1].Sign(hash2, sig2));
    sig2.push_back(SIGHASH_NONE);
    std::vector<unsigned char> sig3;
    uint256 hash3 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_SINGLE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[2].Sign(hash3, sig3));
    sig3.push_back(SIGHASH_SINGLE);

    // Not fussy about order (or even existence) of placeholders or signatures:
    CScript partial1a = CScript() << OP_0 << sig1 << OP_0;
    CScript partial1b = CScript() << OP_0 << OP_0 << sig1;
    CScript partial2a = CScript() << OP_0 << sig2;
    CScript partial2b = CScript() << sig2 << OP_0;
    CScript partial3a = CScript() << sig3;
    CScript partial3b = CScript() << OP_0 << OP_0 << sig3;
    CScript partial3c = CScript() << OP_0 << sig3 << OP_0;
    CScript complete12 = CScript() << OP_0 << sig1 << sig2;
    CScript complete13 = CScript() << OP_0 << sig1 << sig3;
    CScript complete23 = CScript() << OP_0 << sig2 << sig3;
    SignatureData partial1_sigs;
    partial1_sigs.signatures.emplace(keys[0].GetPubKey().GetID(), SigPair(keys[0].GetPubKey(), sig1));
    SignatureData partial2_sigs;
    partial2_sigs.signatures.emplace(keys[1].GetPubKey().GetID(), SigPair(keys[1].GetPubKey(), sig2));
    SignatureData partial3_sigs;
    partial3_sigs.signatures.emplace(keys[2].GetPubKey().GetID(), SigPair(keys[2].GetPubKey(), sig3));

    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == partial1a);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete13);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == partial3c);
}

/**
 * Reproduction of an exception incorrectly raised when parsing a public key inside a TapMiniscript.
 */
BOOST_AUTO_TEST_CASE(sign_invalid_miniscript)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;

    // Create a Taproot output which contains a leaf in which a non-32 bytes push is used where a public key is expected
    // by the Miniscript parser. This offending Script was found by the RPC fuzzer.
    const auto invalid_pubkey{"173d36c8c9c9c9ffffffffffff0200000000021e1e37373721361818181818181e1e1e1e19000000000000000000b19292929292926b006c9b9b9292"_hex_u8};
    TaprootBuilder builder;
    builder.Add(0, {invalid_pubkey}, 0xc0);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    prev.vout.emplace_back(0, GetScriptForDestination(builder.GetOutput()));
    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});
    sig_data.tr_spenddata = builder.GetSpendData();

    // SignSignature can fail but it shouldn't raise an exception (nor crash).
    BOOST_CHECK(!SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

/* P2A input should be considered signed. */
BOOST_AUTO_TEST_CASE(sign_paytoanchor)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;
    prev.vout.emplace_back(0, GetScriptForDestination(PayToAnchor{}));

    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});

    BOOST_CHECK(SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

BOOST_AUTO_TEST_CASE(script_standard_push)
{
    ScriptError err;
    for (int i=0; i<67000; i++) {
        CScript script;
        script << i;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Number " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Number " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    for (unsigned int i=0; i<=MAX_SCRIPT_ELEMENT_SIZE; i++) {
        std::vector<unsigned char> data(i, '\111');
        CScript script;
        script << data;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Length " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Length " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(script_IsPushOnly_on_invalid_scripts)
{
    // IsPushOnly returns false when given a script containing only pushes that
    // are invalid due to truncation. IsPushOnly() is consensus critical
    // because P2SH evaluation uses it, although this specific behavior should
    // not be consensus critical as the P2SH evaluation would fail first due to
    // the invalid push. Still, it doesn't hurt to test it explicitly.
    static const unsigned char direct[] = { 1 };
    BOOST_CHECK(!CScript(direct, direct+sizeof(direct)).IsPushOnly());
}

BOOST_AUTO_TEST_CASE(script_GetScriptAsm)
{
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY));

    std::string derSig("304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090");
    std::string pubKey("03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2");
    std::vector<unsigned char> vchPubKey = ToByteVector(ParseHex(pubKey));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey, true));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "01 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "02 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "03 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "81 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "82 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "83 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey));
}

template <typename T>
CScript ToScript(const T& byte_container)
{
    auto span{MakeUCharSpan(byte_container)};
    return {span.begin(), span.end()};
}

BOOST_AUTO_TEST_CASE(script_byte_array_u8_vector_equivalence)
{
    const CScript scriptPubKey1 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex_v_u8 << OP_CHECKSIG;
    const CScript scriptPubKey2 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BOOST_CHECK(scriptPubKey1 == scriptPubKey2);
}

BOOST_AUTO_TEST_CASE(script_FindAndDelete)
{
    // Exercise the FindAndDelete functionality
    CScript s;
    CScript d;
    CScript expect;

    s = CScript() << OP_1 << OP_2;
    d = CScript(); // delete nothing should be a no-op
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_1 << OP_2 << OP_3;
    d = CScript() << OP_2;
    expect = CScript() << OP_1 << OP_3;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3;
    d = CScript() << OP_3;
    expect = CScript() << OP_1 << OP_4;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 4);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff03"_hex); // PUSH 0x02ff03 onto stack
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex); // PUSH 0x02ff03 PUSH 0x02ff03
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("02"_hex);
    expect = s; // FindAndDelete matches entire opcodes
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("ff"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    // This is an odd edge case: strip of the push-three-bytes
    // prefix, leaving 02ff03 which is push-two-bytes:
    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("03"_hex);
    expect = CScript() << "ff03"_hex << "ff03"_hex;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Byte sequence that spans multiple opcodes:
    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0); // doesn't match 'inside' opcodes
    BOOST_CHECK(s == expect);

    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("02feed51"_hex);
    expect = ToScript("69"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("02feed51"_hex);
    expect = ToScript("516969"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Another weird edge case:
    // End with invalid push (not enough data)...
    s = ToScript("0003feed"_hex);
    d = ToScript("03feed"_hex); // ... can remove the invalid push
    expect = ToScript("00"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0003feed"_hex);
    d = ToScript("00"_hex);
    expect = ToScript("03feed"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);
}

BOOST_AUTO_TEST_CASE(script_HasValidOps)
{
    // Exercise the HasValidOps functionality
    CScript script;
    script = ToScript("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex); // Normal script
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("76a914ff34567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex);
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("ff88ac"_hex); // Script with OP_INVALIDOPCODE explicit
    BOOST_CHECK(!script.HasValidOps());
    script = ToScript("88acc0"_hex); // Script with undefined opcode
    BOOST_CHECK(!script.HasValidOps());
}

BOOST_AUTO_TEST_CASE(code_quantum_envelope_reason_mapping)
{
    const KeyData keys;
    const CScript script_pub_key = CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG;
    const CScriptWitness empty_witness;
    constexpr unsigned int cq_flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_FJARCODE_OPCODES;

    DoTest(script_pub_key,
        CScript() << ParseHex("435101000000"),
        empty_witness,
        SCRIPT_VERIFY_STRICTENC,
        "Code Quantum envelope rejected when activation flag is not set",
        SCRIPT_ERR_CODE_QUANTUM_ACTIVATION_STATE);

    DoTest(script_pub_key,
        CScript() << ParseHex("435101ff0000"),
        empty_witness,
        cq_flags,
        "Code Quantum envelope with unsupported mode",
        SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_MODE);

    DoTest(script_pub_key,
        CScript() << ParseHex("435101000200"),
        empty_witness,
        cq_flags,
        "Code Quantum envelope with unknown algorithm id",
        SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_ALGORITHM_ID);

    DoTest(script_pub_key,
        CScript() << ParseHex("435101000000"),
        empty_witness,
        cq_flags,
        "Code Quantum envelope missing wrapped signature",
        SCRIPT_ERR_CODE_QUANTUM_MISSING_REQUIRED_SIG);

    DoTest(script_pub_key,
        CScript() << ParseHex("43510100000201"),
        empty_witness,
        cq_flags,
        "Code Quantum envelope non-canonical length",
        SCRIPT_ERR_CODE_QUANTUM_NONCANONICAL_ENCODING);

    const CTransaction tx_credit{BuildCreditingTransaction(script_pub_key, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), tx_credit);
    const uint256 legacy_sighash = SignatureHash(script_pub_key, tx_spend, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    uint256 sha3_sighash = legacy_sighash;
    SHA3_256().Write(std::span<const unsigned char>{sha3_sighash.begin(), sha3_sighash.size()}).Finalize(std::span<unsigned char>{sha3_sighash.begin(), sha3_sighash.size()});
    SHA3_256().Write(std::span<const unsigned char>{sha3_sighash.begin(), sha3_sighash.size()}).Finalize(std::span<unsigned char>{sha3_sighash.begin(), sha3_sighash.size()});
    SHA3_256().Write(std::span<const unsigned char>{sha3_sighash.begin(), sha3_sighash.size()}).Finalize(std::span<unsigned char>{sha3_sighash.begin(), sha3_sighash.size()});

    std::vector<unsigned char> wrapped_sig;
    keys.key1C.Sign(sha3_sighash, wrapped_sig);
    wrapped_sig.push_back(SIGHASH_ALL);

    std::vector<unsigned char> cq_envelope;
    cq_envelope.reserve(6 + wrapped_sig.size());
    cq_envelope.push_back('C');
    cq_envelope.push_back('Q');
    cq_envelope.push_back(1);
    cq_envelope.push_back(0);
    cq_envelope.push_back(1);
    cq_envelope.push_back(static_cast<unsigned char>(wrapped_sig.size()));
    cq_envelope.insert(cq_envelope.end(), wrapped_sig.begin(), wrapped_sig.end());

    DoTest(script_pub_key,
        CScript() << cq_envelope,
        empty_witness,
        cq_flags,
        "Code Quantum envelope with active SHA3-256t algorithm",
        SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(code_quantum_registry_matrix_frozen)
{
    const KeyData keys;
    const CScript script_pub_key = CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG;
    const CScriptWitness empty_witness;
    constexpr unsigned int cq_flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_FJARCODE_OPCODES;

    const CTransaction tx_credit{BuildCreditingTransaction(script_pub_key, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), tx_credit);
    const uint256 legacy_sighash = SignatureHash(script_pub_key, tx_spend, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    uint256 sha3_sighash = legacy_sighash;
    SHA3_256().Write(std::span<const unsigned char>{sha3_sighash.begin(), sha3_sighash.size()}).Finalize(std::span<unsigned char>{sha3_sighash.begin(), sha3_sighash.size()});
    SHA3_256().Write(std::span<const unsigned char>{sha3_sighash.begin(), sha3_sighash.size()}).Finalize(std::span<unsigned char>{sha3_sighash.begin(), sha3_sighash.size()});
    SHA3_256().Write(std::span<const unsigned char>{sha3_sighash.begin(), sha3_sighash.size()}).Finalize(std::span<unsigned char>{sha3_sighash.begin(), sha3_sighash.size()});

    std::vector<unsigned char> wrapped_sig_legacy;
    keys.key1C.Sign(legacy_sighash, wrapped_sig_legacy);
    wrapped_sig_legacy.push_back(SIGHASH_ALL);

    std::vector<unsigned char> wrapped_sig_sha3;
    keys.key1C.Sign(sha3_sighash, wrapped_sig_sha3);
    wrapped_sig_sha3.push_back(SIGHASH_ALL);

    const auto make_envelope = [](uint8_t mode, uint8_t algorithm, const std::vector<unsigned char>& wrapped_sig) {
        std::vector<unsigned char> envelope;
        envelope.reserve(6 + wrapped_sig.size());
        envelope.push_back('C');
        envelope.push_back('Q');
        envelope.push_back(1);
        envelope.push_back(mode);
        envelope.push_back(algorithm);
        envelope.push_back(static_cast<unsigned char>(wrapped_sig.size()));
        envelope.insert(envelope.end(), wrapped_sig.begin(), wrapped_sig.end());
        return envelope;
    };

    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, wrapped_sig_legacy),
        empty_witness,
        cq_flags,
        "Code Quantum registry matrix mode0-algo0 active",
        SCRIPT_ERR_OK);

    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/1, wrapped_sig_sha3),
        empty_witness,
        cq_flags,
        "Code Quantum registry matrix mode0-algo1 active",
        SCRIPT_ERR_OK);

    // Algorithm 2 is active (ML-DSA-65 native path); current backend contract still rejects at eval.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/2, wrapped_sig_legacy),
        empty_witness,
        cq_flags,
        "Code Quantum registry matrix known algorithm id 2 (ML-DSA-65) active backend contract",
        SCRIPT_ERR_EVAL_FALSE);

    // Reject precedence guard: malformed envelopes fail canonical encoding before backend dispatch.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/2, std::vector<unsigned char>{0x00}),
        empty_witness,
        cq_flags,
        "Code Quantum registry matrix ML-DSA-65 active malformed envelope rejected by canonical encoding",
        SCRIPT_ERR_CODE_QUANTUM_NONCANONICAL_ENCODING);

    for (const uint8_t unsupported_algorithm : std::vector<uint8_t>{3, 255}) {
        DoTest(script_pub_key,
            CScript() << make_envelope(/*mode=*/0, unsupported_algorithm, wrapped_sig_legacy),
            empty_witness,
            cq_flags,
            strprintf("Code Quantum registry matrix unsupported algorithm id %u", unsupported_algorithm),
            SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_ALGORITHM_ID);
    }

    for (const uint8_t unsupported_mode : std::vector<uint8_t>{1, 2, 127, 255}) {
        DoTest(script_pub_key,
            CScript() << make_envelope(unsupported_mode, /*algorithm=*/0, wrapped_sig_legacy),
            empty_witness,
            cq_flags,
            strprintf("Code Quantum registry matrix unsupported mode id %u", unsupported_mode),
            SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_MODE);
    }

    // Cross-path digest mismatch guards: signatures must fail when routed to the wrong digest path.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/1, wrapped_sig_legacy),
        empty_witness,
        cq_flags,
        "Code Quantum SHA3-256t algorithm with legacy digest signature fails",
        SCRIPT_ERR_EVAL_FALSE);

    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, wrapped_sig_sha3),
        empty_witness,
        cq_flags,
        "Code Quantum legacy algorithm with SHA3-256t digest signature fails",
        SCRIPT_ERR_EVAL_FALSE);

    // Keep hashtype validation deterministic for SHA3-256t path.
    std::vector<unsigned char> wrapped_sig_sha3_bad_hashtype = wrapped_sig_sha3;
    wrapped_sig_sha3_bad_hashtype.back() = 5;
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/1, wrapped_sig_sha3_bad_hashtype),
        empty_witness,
        cq_flags,
        "Code Quantum SHA3-256t path invalid hashtype rejected",
        SCRIPT_ERR_SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_active_algorithm_failure_mode_consensus_contract)
{
    const KeyData keys;
    const CScript script_pub_key = CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG;
    const CScriptWitness empty_witness;
    constexpr unsigned int cq_flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_FJARCODE_OPCODES;

    const CTransaction tx_credit{BuildCreditingTransaction(script_pub_key, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), tx_credit);
    const uint256 legacy_sighash = SignatureHash(script_pub_key, tx_spend, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    std::vector<unsigned char> wrapped_sig_legacy;
    keys.key1C.Sign(legacy_sighash, wrapped_sig_legacy);
    wrapped_sig_legacy.push_back(SIGHASH_ALL);

    const auto make_envelope = [](uint8_t mode, uint8_t algorithm, const std::vector<unsigned char>& wrapped_sig) {
        std::vector<unsigned char> envelope;
        envelope.reserve(6 + wrapped_sig.size());
        envelope.push_back('C');
        envelope.push_back('Q');
        envelope.push_back(1);
        envelope.push_back(mode);
        envelope.push_back(algorithm);
        envelope.push_back(static_cast<unsigned char>(wrapped_sig.size()));
        envelope.insert(envelope.end(), wrapped_sig.begin(), wrapped_sig.end());
        return envelope;
    };

    const auto reject_backend = +[](const std::vector<unsigned char>&,
                                    const std::vector<unsigned char>&,
                                    const CScript&) {
        return codequantum::MLDSA65BackendAdapterResult::REJECTED;
    };
    const auto unavailable_backend = +[](const std::vector<unsigned char>&,
                                         const std::vector<unsigned char>&,
                                         const CScript&) {
        return codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE;
    };

    codequantum::ResetMLDSA65BackendVerifierForTesting();
    codequantum::ResetMLDSA65BackendResultVerifierForTesting();

    // Hard-failure contract: explicit backend reject under active ML-DSA route.
    codequantum::SetMLDSA65BackendResultVerifierForTesting(reject_backend);
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/2, wrapped_sig_legacy),
        empty_witness,
        cq_flags,
        "Code Quantum ML-DSA active algorithm hard-failure consensus contract",
        SCRIPT_ERR_EVAL_FALSE);

    // Soft-failure contract: unavailable backend falls through deterministic
    // adapter path; consensus-visible result remains eval-false for this tuple.
    codequantum::SetMLDSA65BackendResultVerifierForTesting(unavailable_backend);
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/2, wrapped_sig_legacy),
        empty_witness,
        cq_flags,
        "Code Quantum ML-DSA active algorithm soft-failure consensus contract",
        SCRIPT_ERR_EVAL_FALSE);

    codequantum::ResetMLDSA65BackendResultVerifierForTesting();
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_backend_contract_frozen)
{
    const CScript nonempty_script = CScript() << OP_TRUE;

    std::vector<unsigned char> wrapped_sig_ok{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };

    std::vector<unsigned char> pubkey_ok(33, 0x00);
    pubkey_ok[0] = 0x02;

    std::vector<unsigned char> pubkey_uncompressed_ok(65, 0x00);
    pubkey_uncompressed_ok[0] = 0x04;

    codequantum::MLDSA65VerifyError verify_error = codequantum::MLDSA65VerifyError::OK;

    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature({}, pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(std::vector<unsigned char>{0x30, 0x00, static_cast<unsigned char>(SIGHASH_ALL)}, pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(std::vector<unsigned char>(74, 0x01), pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(std::vector<unsigned char>{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, static_cast<unsigned char>(SIGHASH_ALL)}, pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(std::vector<unsigned char>{0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, static_cast<unsigned char>(SIGHASH_ALL)}, pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(std::vector<unsigned char>{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00}, pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, {}, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, std::vector<unsigned char>(66, 0x02), nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, std::vector<unsigned char>(33, 0x00), nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, std::vector<unsigned char>(65, 0x00), nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_ok, CScript()));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed({}, pubkey_ok, nonempty_script, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::WRAPPED_SIG_INVALID));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_ok, std::vector<unsigned char>(33, 0x00), nonempty_script, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::PUBKEY_INVALID));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_ok, pubkey_ok, CScript(), &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::EMPTY_SCRIPT_CODE));

    // Even with a shape-valid input tuple, backend remains deterministic false until crypto wiring lands.
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_uncompressed_ok, nonempty_script));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_ok, pubkey_ok, nonempty_script, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_backend_hook_contract_frozen)
{
    const CScript nonempty_script = CScript() << OP_TRUE;
    const std::vector<unsigned char> wrapped_sig_ok{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> pubkey_ok(33, 0x00);
    pubkey_ok[0] = 0x02;

    const auto accept_backend = +[](const std::vector<unsigned char>&,
                                    const std::vector<unsigned char>&,
                                    const CScript&) {
        return true;
    };

    codequantum::MLDSA65VerifyError verify_error = codequantum::MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED;

    codequantum::SetMLDSA65BackendVerifierForTesting(accept_backend);
    BOOST_CHECK(codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_ok, nonempty_script));
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_ok, pubkey_ok, nonempty_script, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));

    codequantum::ResetMLDSA65BackendVerifierForTesting();
    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_ok, nonempty_script));

    const auto reject_backend = +[](const std::vector<unsigned char>&,
                                    const std::vector<unsigned char>&,
                                    const CScript&) {
        return codequantum::MLDSA65BackendAdapterResult::REJECTED;
    };
    const auto unavailable_backend = +[](const std::vector<unsigned char>&,
                                         const std::vector<unsigned char>&,
                                         const CScript&) {
        return codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE;
    };

    codequantum::SetMLDSA65BackendResultVerifierForTesting(reject_backend);
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_ok, pubkey_ok, nonempty_script, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));

    codequantum::SetMLDSA65BackendResultVerifierForTesting(unavailable_backend);
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_ok, pubkey_ok, nonempty_script, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));

    codequantum::ResetMLDSA65BackendResultVerifierForTesting();
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_backend_hook_gating_contract_frozen)
{
    const CScript nonempty_script = CScript() << OP_TRUE;
    const std::vector<unsigned char> wrapped_sig_ok{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> pubkey_ok(33, 0x00);
    pubkey_ok[0] = 0x02;

    g_mldsa_backend_hook_calls = 0;
    codequantum::SetMLDSA65BackendVerifierForTesting(CountingMLDSABackendHook);
    codequantum::ResetMLDSA65BackendResultVerifierForTesting();

    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(std::vector<unsigned char>{}, pubkey_ok, nonempty_script));
    BOOST_CHECK_EQUAL(g_mldsa_backend_hook_calls, 0);

    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, std::vector<unsigned char>(33, 0x00), nonempty_script));
    BOOST_CHECK_EQUAL(g_mldsa_backend_hook_calls, 0);

    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_ok, CScript()));
    BOOST_CHECK_EQUAL(g_mldsa_backend_hook_calls, 0);

    BOOST_CHECK(!codequantum::VerifyMLDSA65Signature(wrapped_sig_ok, pubkey_ok, nonempty_script));
    BOOST_CHECK_EQUAL(g_mldsa_backend_hook_calls, 1);

    codequantum::ResetMLDSA65BackendVerifierForTesting();
    codequantum::ResetMLDSA65BackendResultVerifierForTesting();
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_backend_adapter_vector_contract_frozen)
{
    const CScript script_known_good = CScript() << OP_TRUE << OP_DROP;
    const CScript script_known_good_2 = CScript() << OP_TRUE;
    const CScript script_other = CScript() << OP_TRUE;
    const std::vector<unsigned char> wrapped_sig_known_good{
        0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_NONE),
    };
    std::vector<unsigned char> pubkey_known_good(33, 0x11);
    pubkey_known_good[0] = 0x03;

    const std::vector<unsigned char> wrapped_sig_known_good_2{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> pubkey_known_good_2(33, 0x22);
    pubkey_known_good_2[0] = 0x02;

    std::vector<unsigned char> wrapped_sig_other = wrapped_sig_known_good;
    wrapped_sig_other.back() = static_cast<unsigned char>(SIGHASH_ALL);

    std::vector<unsigned char> pubkey_other = pubkey_known_good;
    pubkey_other[0] = 0x02;

    codequantum::MLDSA65VerifyError verify_error = codequantum::MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED;

    codequantum::ResetMLDSA65BackendVerifierForTesting();

    BOOST_CHECK(codequantum::VerifyMLDSA65Signature(wrapped_sig_known_good, pubkey_known_good, script_known_good));
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_known_good, pubkey_known_good, script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));

    BOOST_CHECK(codequantum::VerifyMLDSA65Signature(wrapped_sig_known_good_2, pubkey_known_good_2, script_known_good_2));
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_known_good_2, pubkey_known_good_2, script_known_good_2, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_other, pubkey_known_good, script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_known_good, pubkey_other, script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_known_good, pubkey_known_good, script_other, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_native_provider_contract_frozen)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    const CScript script_native = CScript() << OP_FALSE;
    const std::vector<unsigned char> wrapped_sig_shape_valid{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    const std::vector<unsigned char> wrapped_sig_shape_valid_none{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_NONE),
    };
    std::vector<unsigned char> pubkey_shape_valid(33, 0x44);
    pubkey_shape_valid[0] = 0x02;

    const CScript fallback_script_known_good = CScript() << OP_TRUE << OP_DROP;
    const std::vector<unsigned char> fallback_sig_known_good{
        0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_NONE),
    };
    std::vector<unsigned char> fallback_pubkey_known_good(33, 0x11);
    fallback_pubkey_known_good[0] = 0x03;
    CScript script_non_vector = script_native;
    script_non_vector << OP_1;

    codequantum::MLDSA65VerifyError verify_error = codequantum::MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED;
    codequantum::ResetMLDSA65NativeBackendTelemetryStateForTesting();

    g_mldsa_native_provider_calls = 0;
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderVerified});
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65NativeBackend({}, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    auto telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(telemetry.last_tag),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendTelemetryTag::REJECT_WRAPPED_SIG));
    BOOST_CHECK_EQUAL(telemetry.reject_wrapped_sig, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65NativeBackend(wrapped_sig_shape_valid, std::vector<unsigned char>{}, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(telemetry.last_tag),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendTelemetryTag::REJECT_PUBKEY));
    BOOST_CHECK_EQUAL(telemetry.reject_pubkey, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65NativeBackend(wrapped_sig_shape_valid, pubkey_shape_valid, CScript())),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(telemetry.last_tag),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendTelemetryTag::REJECT_EMPTY_SCRIPT));
    BOOST_CHECK_EQUAL(telemetry.reject_empty_script, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 0);

    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_EQUAL(telemetry.init_attempts, static_cast<uint64_t>(0));
    BOOST_CHECK_GE(telemetry.verify_invocations, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(telemetry.verified, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(telemetry.last_tag),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendTelemetryTag::VERIFIED));

    // Native VERIFIED short-circuit contract: for a non-vector tuple that the
    // deterministic adapter fallback would reject, native VERIFIED must win.
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderUnavailable});
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 2);
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderVerified});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 3);

    // Native REJECTED short-circuit contract: for a known-good fallback tuple,
    // native REJECTED must win over deterministic adapter verification.
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderRejected});
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 4);
    telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_EQUAL(telemetry.reject_backend, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(telemetry.last_tag),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendTelemetryTag::REJECT_BACKEND));

    // Native return-code normalization contract: unknown enum values map to
    // UNAVAILABLE and therefore fall through to deterministic adapter behavior.
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderInvalidEnum});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 6);
    telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_GE(telemetry.reject_unavailable, static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(telemetry.last_tag),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendTelemetryTag::REJECT_UNAVAILABLE));

    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderUnavailable});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 7);

    // Landing-seam contract: implementation-binding test override takes
    // precedence over default binding during lazy init.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::ResetMLDSA65NativeBackendTelemetryStateForTesting();
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryVerified);
    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderRejected});
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);
    telemetry = codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_GE(telemetry.init_attempts, static_cast<uint64_t>(1));
    BOOST_CHECK_GE(telemetry.verify_invocations, static_cast<uint64_t>(1));

    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    // Implementation-seam flap stability: repeated set->reset->set transitions
    // must keep lazy-init precedence deterministic without sticky state leaks.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryVerified);

    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderRejected});
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderVerified});
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    // Controlled non-noop implementation seam contract: a test-only
    // implementation callback can actively verify specific tuples.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderImplementationProbe});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid_none, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid_none, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 0);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    // Precedence contract: explicit provider register overrides pending
    // implementation override once initialized; implementation override wins
    // again after clear (re-triggering lazy init).
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderRejected});
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderVerified});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();

    // Binding-shape contract: availability-only bindings are unsupported and must
    // fall back to deterministic adapter behavior.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    codequantum::RegisterMLDSA65NativeBackendBinding({NativeProviderAvailableTrue, nullptr});
    BOOST_CHECK(!codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 0);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryVerified);
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 2);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    codequantum::ClearMLDSA65NativeBackendBinding();
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 3);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 2);

    // Register last-writer contract: with consecutive register calls, the most
    // recent binding must deterministically control verify dispatch.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderVerified});
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderRejected});
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderVerified});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderRejected});
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 2);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ClearMLDSA65NativeBackendBinding();
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 3);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();

    // Lazy-init half-binding contract: availability-only default factory output
    // is unsupported and must keep native backend unavailable with adapter fallback.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryAvailabilityOnly);
    g_mldsa_native_default_factory_calls = 0;

    BOOST_CHECK(!codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 3);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    // Disable-state equivalence contract: explicit null binding registration is
    // behaviorally equivalent to clear and allows lazy default re-init.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryVerified);
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, nullptr});
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);

    // Availability side-effect contract: once lazy init is completed, repeated
    // availability queries must not mutate provider/default-factory call counts.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryVerified);
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 0);
    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 0);

    // Bridge-ready gating and handoff contract in native provider path.
#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    codequantum::ResetMLDSA65ExternalBackendRequestObserverForTesting();
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
    g_mldsa_native_external_bridge_verify_calls = 0;
    g_mldsa_external_bridge_calls = 0;
    codequantum::RegisterMLDSA65NativeBackendBinding({NativeProviderExternalBridgeAvailable, NativeProviderExternalBridgeVerify});

    // Gating purity: when bridge is not ready, provider stays unavailable,
    // fallback is deterministic, and no external-native verify dispatch occurs.
    BOOST_CHECK(!codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 0);
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 0);

    // Positive handoff: once bridge becomes ready, same binding transitions to
    // external dispatch and native path result changes accordingly.
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerified);
    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 1);

    // Negative handoff: if external bridge readiness is removed, same binding
    // must become unavailable again and return to deterministic fallback.
    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    BOOST_CHECK(!codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 1);

    // Bridge flap stability: if readiness is restored again on the same binding,
    // dispatch should resume without sticky unavailable state.
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerified);
    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 2);
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 2);

    // Counter-scope purity: readiness polling alone must not advance external
    // dispatch counters; only verify dispatch in ready state may do so.
    const int native_external_calls_before_poll = g_mldsa_native_external_bridge_verify_calls;
    const int external_bridge_calls_before_poll = g_mldsa_external_bridge_calls;
    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, native_external_calls_before_poll);
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, external_bridge_calls_before_poll);

    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, native_external_calls_before_poll + 1);
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, external_bridge_calls_before_poll + 1);

    // Native handoff callback-isolation contract: external observer/result-code
    // hooks must preserve callback ordering and verifier bypass behavior.
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerifiedWithTrace);
    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequestWithTrace);
    codequantum::SetMLDSA65ExternalBackendResultCodeVerifierForTesting(ExternalBridgeResultCodeFromRequestWithTrace);
    g_mldsa_external_result_code_to_return = codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED;
    g_mldsa_external_callback_trace.clear();
    g_mldsa_external_bridge_calls = 0;
    g_mldsa_native_external_bridge_verify_calls = 0;
    codequantum::RegisterMLDSA65NativeBackendBinding({NativeProviderExternalBridgeAvailable, NativeProviderExternalBridgeVerify});

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_external_callback_trace, std::string{"OR"});
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 0);
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 1);

    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
    g_mldsa_external_callback_trace.clear();
    g_mldsa_external_bridge_calls = 0;
    g_mldsa_native_external_bridge_verify_calls = 0;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_external_callback_trace, std::string{"OV"});
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 1);

    // Mutation rejection through native handoff: observer mutation must trigger
    // digest immutability rejection before external verifier dispatch.
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerifiedWithTrace);
    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequestMutateDigest);
    g_mldsa_external_callback_trace.clear();
    g_mldsa_external_bridge_calls = 0;
    g_mldsa_native_external_bridge_verify_calls = 0;
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_external_callback_trace, std::string{"M"});
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 0);
    BOOST_CHECK_EQUAL(g_mldsa_native_external_bridge_verify_calls, 1);

    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequestWithTrace);
#endif

    // Verify-dispatch purity contract: when native verify returns UNAVAILABLE,
    // fallback remains deterministic and does not mutate lazy-init/provider state.
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderUnavailable});
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(fallback_sig_known_good, fallback_pubkey_known_good, fallback_script_known_good, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_native, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 2);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    // Cleanup/no-leakage contract: after explicit reset sequence, provider state
    // must return to disabled baseline with deterministic adapter fallback.
    codequantum::SetDefaultMLDSA65NativeBackendBindingFactoryForTesting(NativeDefaultBindingFactoryVerified);
    codequantum::SetMLDSA65NativeBackendImplementationBindingForTesting({nullptr, NativeProviderRejected});
    codequantum::RegisterMLDSA65NativeBackendBinding({nullptr, NativeProviderVerified});
    codequantum::ClearMLDSA65NativeBackendBinding();

    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    g_mldsa_native_provider_calls = 0;
    g_mldsa_native_default_factory_calls = 0;

    BOOST_CHECK(!codequantum::MLDSA65NativeBackendAvailable());
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_provider_calls, 0);
    BOOST_CHECK_EQUAL(g_mldsa_native_default_factory_calls, 0);

    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    codequantum::ResetMLDSA65ExternalBackendRequestObserverForTesting();
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
#endif
#endif
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_native_builtin_secp256k1_verify_contract)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND) && defined(ENABLE_MLDSA65_NATIVE_BACKEND_SECP256K1_VERIFY)
    const KeyData keys;
    const CScript script_code = CScript() << OP_TRUE << OP_DROP << OP_1;
    constexpr unsigned char sighash_type = static_cast<unsigned char>(SIGHASH_ALL);

    const std::array<unsigned char, 32> digest =
        ComputeExpectedNativeBuiltinPrehash(script_code, sighash_type);
    const uint256 digest_uint256(std::span<const unsigned char>(digest.data(), digest.size()));

    std::vector<unsigned char> der_sig;
    BOOST_REQUIRE(keys.key1C.Sign(digest_uint256, der_sig));
    std::vector<unsigned char> wrapped_sig = der_sig;
    wrapped_sig.push_back(sighash_type);
    const std::vector<unsigned char> pubkey = ToByteVector(keys.pubkey1C);

    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::ResetMLDSA65NativeBackendTelemetryStateForTesting();

    codequantum::MLDSA65VerifyError verify_error = codequantum::MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED;
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig, pubkey, script_code, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));

    const codequantum::MLDSA65NativeBackendTelemetryState telemetry_verified =
        codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_GE(telemetry_verified.init_attempts, static_cast<uint64_t>(1));
    BOOST_CHECK_GE(telemetry_verified.verify_invocations, static_cast<uint64_t>(1));
    BOOST_CHECK_GE(telemetry_verified.verified, static_cast<uint64_t>(1));

    std::vector<unsigned char> wrapped_sig_tampered = wrapped_sig;
    BOOST_REQUIRE(wrapped_sig_tampered.size() > 2);
    wrapped_sig_tampered[wrapped_sig_tampered.size() - 2] ^= 0x01;

    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_tampered, pubkey, script_code, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));

    const codequantum::MLDSA65NativeBackendTelemetryState telemetry_rejected =
        codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_GE(telemetry_rejected.reject_backend, static_cast<uint64_t>(1));

    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
#else
    BOOST_CHECK(true);
#endif
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_native_signer_callback_contract)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND)
    const std::vector<unsigned char> key_material(32, 0x42);
    const CScript script_code = CScript() << OP_TRUE;
    const CScript script_code_alt = CScript() << OP_FALSE << OP_1;
    constexpr unsigned char sighash_type = static_cast<unsigned char>(SIGHASH_ALL);
    constexpr unsigned char sighash_type_alt = static_cast<unsigned char>(SIGHASH_NONE);

    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ResetMLDSA65NativeBackendSignerForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();

    std::vector<unsigned char> out_wrapped_sig;
    out_wrapped_sig = {0x42};
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code, sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::UNAVAILABLE));
    BOOST_CHECK(out_wrapped_sig.empty());

    // Deterministic unavailable fallback policy: unavailable bindings must not
    // leave stale output bytes in the signature buffer.
    g_mldsa_native_signer_calls = 0;
    codequantum::RegisterMLDSA65NativeBackendBinding({NativeProviderAvailableFalse, nullptr, NativeSignerDeterministic});
    out_wrapped_sig = {0x99};
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code, sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::UNAVAILABLE));
    BOOST_CHECK(out_wrapped_sig.empty());
    BOOST_CHECK_EQUAL(g_mldsa_native_signer_calls, 0);
    codequantum::ClearMLDSA65NativeBackendBinding();

    g_mldsa_native_signer_calls = 0;
    g_mldsa_native_last_sign_prehash_set = false;
    codequantum::SetMLDSA65NativeBackendSignerForTesting(NativeSignerDeterministic);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code, sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::SIGNED));
    BOOST_CHECK_EQUAL(g_mldsa_native_signer_calls, 1);
    BOOST_CHECK(!out_wrapped_sig.empty());
    BOOST_CHECK_EQUAL(out_wrapped_sig.back(), sighash_type);
    BOOST_CHECK(g_mldsa_native_last_sign_prehash_set);
    const std::array<unsigned char, 32> expected_prehash =
        codequantum::ComputeMLDSA65NativeSigningPrehash(script_code, sighash_type);
    BOOST_CHECK(g_mldsa_native_last_sign_prehash == expected_prehash);

    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code_alt, sighash_type_alt, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::SIGNED));
    const std::array<unsigned char, 32> expected_prehash_alt =
        codequantum::ComputeMLDSA65NativeSigningPrehash(script_code_alt, sighash_type_alt);
    BOOST_CHECK(g_mldsa_native_last_sign_prehash == expected_prehash_alt);
    BOOST_CHECK(expected_prehash != expected_prehash_alt);

    g_mldsa_native_signer_calls = 0;
    codequantum::SetMLDSA65NativeBackendSignerForTesting(NativeSignerMalformed);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code, sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_native_signer_calls, 1);
    BOOST_CHECK(out_wrapped_sig.empty());

    g_mldsa_native_signer_calls = 0;
    codequantum::SetMLDSA65NativeBackendSignerForTesting(NativeSignerInvalidEnum);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code, sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::UNAVAILABLE));
    BOOST_CHECK_EQUAL(g_mldsa_native_signer_calls, 1);
    BOOST_CHECK(out_wrapped_sig.empty());

    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend({}, script_code, sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::REJECTED));
    BOOST_CHECK(out_wrapped_sig.empty());
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, CScript(), sighash_type, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::REJECTED));
    BOOST_CHECK(out_wrapped_sig.empty());
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::SignMLDSA65NativeBackend(key_material, script_code, 0x00, out_wrapped_sig)),
                      static_cast<unsigned char>(codequantum::MLDSA65NativeBackendSignResult::REJECTED));
    BOOST_CHECK(out_wrapped_sig.empty());

    codequantum::ResetMLDSA65NativeBackendSignerForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
#else
    BOOST_CHECK(true);
#endif
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_native_scaffold_default_handoff_contract_frozen)
{
#if defined(ENABLE_MLDSA65_NATIVE_BACKEND) && defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
    const CScript script_native = CScript() << OP_FALSE;
    const std::vector<unsigned char> wrapped_sig_shape_valid{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> pubkey_shape_valid(33, 0x44);
    pubkey_shape_valid[0] = 0x02;
    CScript script_non_vector = script_native;
    script_non_vector << OP_1;

    codequantum::MLDSA65VerifyError verify_error = codequantum::MLDSA65VerifyError::BACKEND_NOT_IMPLEMENTED;

    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
    codequantum::ResetMLDSA65NativeBackendTelemetryStateForTesting();
    codequantum::ResetMLDSA65ExternalBackendRequestObserverForTesting();
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
    g_mldsa_external_bridge_calls = 0;

    // Without an external verifier callback, default bridge binding is present
    // but not ready; non-vector tuple must still reject.
    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    BOOST_CHECK(!codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::BACKEND_REJECTED));

    // Once bridge verifier is installed, default lazy-init handoff must route
    // through native provider and verify same non-vector tuple successfully.
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerified);
    BOOST_CHECK(codequantum::VerifyMLDSA65SignatureDetailed(wrapped_sig_shape_valid, pubkey_shape_valid, script_non_vector, &verify_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(verify_error), static_cast<unsigned char>(codequantum::MLDSA65VerifyError::OK));
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 1);

    const codequantum::MLDSA65NativeBackendTelemetryState telemetry =
        codequantum::GetMLDSA65NativeBackendTelemetryState();
    BOOST_CHECK_GE(telemetry.init_attempts, static_cast<uint64_t>(1));
    BOOST_CHECK_GE(telemetry.verify_invocations, static_cast<uint64_t>(1));
    BOOST_CHECK_GE(telemetry.verified, static_cast<uint64_t>(1));

    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    codequantum::ResetMLDSA65ExternalBackendRequestObserverForTesting();
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
    codequantum::ResetDefaultMLDSA65NativeBackendBindingFactoryForTesting();
    codequantum::ResetMLDSA65NativeBackendImplementationBindingForTesting();
    codequantum::ClearMLDSA65NativeBackendBinding();
#endif
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_external_backend_scaffold_contract_frozen)
{
#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD)
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendScaffoldEnabled());
#else
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendScaffoldEnabled());
#endif

#if defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendHeaderDetected());
#else
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendHeaderDetected());
#endif
}

BOOST_AUTO_TEST_CASE(code_quantum_scripthash32_signing_recursion_contract)
{
    FillableSigningProvider keystore;
    const CKey key = GenerateRandomKey(/*compressed=*/true);
    BOOST_REQUIRE(keystore.AddKey(key));

    const CScript redeem_script = GetScriptForDestination(PKHash(key.GetPubKey()));
    BOOST_REQUIRE(keystore.AddCScript(redeem_script));

    const uint256 redeem_hash256 = Hash(redeem_script);
    const CScript quantum_script_pub_key = CScript() << OP_HASH256 << ToByteVector(redeem_hash256) << OP_EQUAL;
    BOOST_CHECK(quantum_script_pub_key.IsPayToScriptHash32());

    CMutableTransaction tx_from = BuildCreditingTransaction(quantum_script_pub_key);
    CMutableTransaction tx_to = BuildSpendingTransaction(CScript(), CScriptWitness(), CTransaction(tx_from));

    SignatureData dummy;
    BOOST_CHECK(SignSignature(keystore, CTransaction(tx_from), tx_to, 0, SIGHASH_ALL, dummy));

    const SignatureData sig_data = DataFromTransaction(tx_to, 0, tx_from.vout[0]);
    BOOST_CHECK(!sig_data.scriptSig.empty());

    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(tx_to.vin[0].scriptSig,
                             tx_from.vout[0].scriptPubKey,
                             &tx_to.vin[0].scriptWitness,
                             SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
                             MutableTransactionSignatureChecker(&tx_to,
                                                                 0,
                                                                 tx_from.vout[0].nValue,
                                                                 MissingDataBehavior::FAIL),
                             &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_external_backend_bridge_contract_frozen)
{
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendRequestVersionSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestVersionSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION + 1));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendCapabilitiesSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendCapabilitiesSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PREHASHED_SIGHASH));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendCapabilitiesSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE | (1U << 31)));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendCapabilityProfileSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendCapabilityProfileSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1 + 1));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendInterfaceIdSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID));
    std::array<unsigned char, 16> unsupported_interface_id = codequantum::MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID;
    unsupported_interface_id[15] = '2';
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendInterfaceIdSupported(unsupported_interface_id));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendResultCodeSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_VERIFIED));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendResultCodeSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendResultCodeSupported(codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_UNAVAILABLE));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendResultCodeSupported(static_cast<uint8_t>(255)));
    BOOST_CHECK_EQUAL(codequantum::MLDSA65_EXTERNAL_BACKEND_MAX_WRAPPED_SIG_SIZE, static_cast<size_t>(73));
    BOOST_CHECK_EQUAL(codequantum::MLDSA65_EXTERNAL_BACKEND_MAX_PUBKEY_SIZE, static_cast<size_t>(65));
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/9,
                                                                         /*pubkey_size=*/33,
                                                                         /*der_sig_size=*/8,
                                                                         /*pubkey_payload_size=*/32));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/0,
                                                                          /*pubkey_size=*/33,
                                                                          /*der_sig_size=*/8,
                                                                          /*pubkey_payload_size=*/32));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/74,
                                                                          /*pubkey_size=*/33,
                                                                          /*der_sig_size=*/8,
                                                                          /*pubkey_payload_size=*/32));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/9,
                                                                          /*pubkey_size=*/0,
                                                                          /*der_sig_size=*/8,
                                                                          /*pubkey_payload_size=*/32));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/9,
                                                                          /*pubkey_size=*/66,
                                                                          /*der_sig_size=*/8,
                                                                          /*pubkey_payload_size=*/32));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/9,
                                                                          /*pubkey_size=*/33,
                                                                          /*der_sig_size=*/7,
                                                                          /*pubkey_payload_size=*/32));
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestSizesSupported(/*wrapped_sig_size=*/9,
                                                                          /*pubkey_size=*/33,
                                                                          /*der_sig_size=*/8,
                                                                          /*pubkey_payload_size=*/31));
    const std::vector<unsigned char> helper_wrapped_sig_shape_valid{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> helper_pubkey_shape_valid(33, 0x66);
    helper_pubkey_shape_valid[0] = 0x02;
    const CScript helper_script_native = CScript() << OP_FALSE;
    codequantum::MLDSA65ExternalBackendRequest pointer_helper_ok{
        codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION,
        codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE,
        codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1,
        codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_MAGIC,
        codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_SHAPE_HASH,
        codequantum::MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID,
        &helper_wrapped_sig_shape_valid,
        &helper_pubkey_shape_valid,
        &helper_script_native,
        static_cast<size_t>(0),
        static_cast<size_t>(8),
        static_cast<size_t>(1),
        static_cast<size_t>(32),
        static_cast<unsigned char>(SIGHASH_ALL),
        true,
        codequantum::MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG,
        std::array<unsigned char, 32>{},
        std::array<unsigned char, 32>{},
    };
    pointer_helper_ok.request_content_digest32 = codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(pointer_helper_ok);
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendRequestPointersSupported(pointer_helper_ok));
    codequantum::MLDSA65ExternalBackendRequest pointer_helper_bad = pointer_helper_ok;
    pointer_helper_bad.wrapped_sig = nullptr;
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestPointersSupported(pointer_helper_bad));
    pointer_helper_bad = pointer_helper_ok;
    pointer_helper_bad.pubkey = nullptr;
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestPointersSupported(pointer_helper_bad));
    pointer_helper_bad = pointer_helper_ok;
    pointer_helper_bad.script_code = nullptr;
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendRequestPointersSupported(pointer_helper_bad));

    const std::array<unsigned char, 32> digest_baseline =
        codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(pointer_helper_ok);
    BOOST_CHECK((digest_baseline != std::array<unsigned char, 32>{}));
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(pointer_helper_ok) == digest_baseline);

    // Stability contract: request_content_digest32 is output metadata and must not feed into digest input.
    codequantum::MLDSA65ExternalBackendRequest digest_stability = pointer_helper_ok;
    digest_stability.request_content_digest32[0] = 0x42;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_stability) == digest_baseline);

    codequantum::MLDSA65ExternalBackendRequest digest_mutation = pointer_helper_ok;
    digest_mutation.request_version += 1;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    // LE/full-width contract: higher-order byte mutations must affect digest too.
    const codequantum::MLDSA65ExternalBackendRequest digest_version_lowbyte = digest_mutation;
    codequantum::MLDSA65ExternalBackendRequest digest_version_nextbyte = pointer_helper_ok;
    digest_version_nextbyte.request_version += 0x100;
    const std::array<unsigned char, 32> digest_version_nextbyte_hash =
        codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_version_nextbyte);
    BOOST_CHECK(digest_version_nextbyte_hash != digest_baseline);
    BOOST_CHECK(digest_version_nextbyte_hash != codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_version_lowbyte));

    codequantum::MLDSA65ExternalBackendRequest digest_offset_nextbyte = pointer_helper_ok;
    digest_offset_nextbyte.der_sig_offset = static_cast<size_t>(0x100);
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_offset_nextbyte) != digest_baseline);

    digest_mutation = pointer_helper_ok;
    digest_mutation.capability_flags ^= codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PREHASHED_SIGHASH;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    digest_mutation = pointer_helper_ok;
    digest_mutation.external_backend_interface_id[0] ^= 1;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    digest_mutation = pointer_helper_ok;
    digest_mutation.sighash_type = static_cast<unsigned char>(SIGHASH_NONE);
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    std::vector<unsigned char> helper_wrapped_sig_shape_valid_alt = helper_wrapped_sig_shape_valid;
    helper_wrapped_sig_shape_valid_alt[4] ^= 1;
    digest_mutation = pointer_helper_ok;
    digest_mutation.wrapped_sig = &helper_wrapped_sig_shape_valid_alt;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    std::vector<unsigned char> helper_pubkey_shape_valid_alt = helper_pubkey_shape_valid;
    helper_pubkey_shape_valid_alt[10] ^= 1;
    digest_mutation = pointer_helper_ok;
    digest_mutation.pubkey = &helper_pubkey_shape_valid_alt;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    const CScript helper_script_native_alt = CScript() << OP_1;
    digest_mutation = pointer_helper_ok;
    digest_mutation.script_code = &helper_script_native_alt;
    BOOST_CHECK(codequantum::ComputeMLDSA65ExternalBackendRequestContentDigest(digest_mutation) != digest_baseline);

    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::TranslateMLDSA65ExternalBackendResultCode(codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_VERIFIED)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::VERIFIED));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::TranslateMLDSA65ExternalBackendResultCode(codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::TranslateMLDSA65ExternalBackendResultCode(codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_UNAVAILABLE)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(codequantum::TranslateMLDSA65ExternalBackendResultCode(static_cast<uint8_t>(255))),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE));

    const CScript script_native = CScript() << OP_FALSE;
    const std::vector<unsigned char> wrapped_sig_shape_valid{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    const std::vector<unsigned char> wrapped_sig_shape_valid_none{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_NONE),
    };
    std::vector<unsigned char> pubkey_shape_valid(33, 0x66);
    pubkey_shape_valid[0] = 0x02;

    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    BOOST_CHECK(!codequantum::MLDSA65ExternalBackendBridgeReady());
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE));

    const codequantum::MLDSA65NativeBackendBinding binding_before = codequantum::GetDefaultMLDSA65NativeBackendBinding();
#if defined(ENABLE_MLDSA65_EXTERNAL_BACKEND_SCAFFOLD) && defined(HAVE_MLDSA65_EXTERNAL_BACKEND_HEADER)
    BOOST_CHECK(binding_before.is_available != nullptr);
    BOOST_CHECK(binding_before.verify != nullptr);
    BOOST_CHECK(!binding_before.is_available());

    g_mldsa_external_bridge_calls = 0;
    g_mldsa_external_request_observer_calls = 0;
    g_mldsa_external_result_code_to_return = codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_UNAVAILABLE;
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerified);
    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequest);
    BOOST_CHECK(codequantum::MLDSA65ExternalBackendBridgeReady());

    const codequantum::MLDSA65NativeBackendBinding binding_after = codequantum::GetDefaultMLDSA65NativeBackendBinding();
    BOOST_CHECK(binding_after.is_available != nullptr);
    BOOST_CHECK(binding_after.verify != nullptr);
    BOOST_CHECK(binding_after.is_available());

    const codequantum::MLDSA65BackendAdapterResult result =
        binding_after.verify(wrapped_sig_shape_valid, pubkey_shape_valid, script_native);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(result), static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::VERIFIED));
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_external_request_observer_calls, 1);
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_request_version, codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_VERSION);
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_capability_flags, codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITIES_BASELINE);
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_capability_profile_id, codequantum::MLDSA65_EXTERNAL_BACKEND_CAPABILITY_PROFILE_BASELINE_V1);
    BOOST_CHECK(g_mldsa_external_observed_request_magic == codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_MAGIC);
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_request_shape_hash, codequantum::MLDSA65_EXTERNAL_BACKEND_REQUEST_SHAPE_HASH);
    BOOST_CHECK(g_mldsa_external_observed_interface_id == codequantum::MLDSA65_EXTERNAL_BACKEND_INTERFACE_ID);
    BOOST_CHECK(g_mldsa_external_observed_wrapped_sig_ptr == &wrapped_sig_shape_valid);
    BOOST_CHECK(g_mldsa_external_observed_pubkey_ptr == &pubkey_shape_valid);
    BOOST_CHECK(g_mldsa_external_observed_script_code_ptr == &script_native);
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_der_sig_size, static_cast<size_t>(8));
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_pubkey_payload_size, static_cast<size_t>(32));
    BOOST_CHECK_EQUAL(g_mldsa_external_observed_sighash_type, static_cast<unsigned char>(SIGHASH_ALL));
    BOOST_CHECK(g_mldsa_external_observed_pubkey_is_compressed);
    BOOST_CHECK(g_mldsa_external_observed_prehash_domain_tag == codequantum::MLDSA65_EXTERNAL_BACKEND_PREHASH_DOMAIN_TAG);
    BOOST_CHECK(g_mldsa_external_observed_prehashed_sighash32 ==
                ComputeExpectedExternalPrehashedSighash(script_native, static_cast<unsigned char>(SIGHASH_ALL)));
    BOOST_CHECK(g_mldsa_external_observed_request_content_digest32 == g_mldsa_external_observed_request_content_digest32_recomputed);

    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid_none, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::VERIFIED));
    BOOST_CHECK(g_mldsa_external_observed_prehashed_sighash32 ==
                ComputeExpectedExternalPrehashedSighash(script_native, static_cast<unsigned char>(SIGHASH_NONE)));

    codequantum::SetMLDSA65ExternalBackendResultCodeVerifierForTesting(ExternalBridgeResultCodeFromRequest);
    g_mldsa_external_result_code_to_return = codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_VERIFIED;
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::VERIFIED));
    g_mldsa_external_result_code_to_return = codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED;
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    g_mldsa_external_result_code_to_return = static_cast<uint8_t>(255);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::UNAVAILABLE));
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();

    // Callback order contract: observer runs first, then result-code verifier.
    g_mldsa_external_callback_trace.clear();
    g_mldsa_external_result_code_to_return = codequantum::MLDSA65_EXTERNAL_BACKEND_RESULT_CODE_REJECTED;
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerifiedWithTrace);
    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequestWithTrace);
    codequantum::SetMLDSA65ExternalBackendResultCodeVerifierForTesting(ExternalBridgeResultCodeFromRequestWithTrace);
    g_mldsa_external_bridge_calls = 0;
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_external_callback_trace, std::string{"OR"});
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 0);

    // Without result-code verifier, observer precedes verifier and fallback is bypassed.
    g_mldsa_external_callback_trace.clear();
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::VERIFIED));
    BOOST_CHECK_EQUAL(g_mldsa_external_callback_trace, std::string{"OV"});

    // Immutability contract: observer mutation causes digest mismatch -> REJECTED before verifier dispatch.
    g_mldsa_external_callback_trace.clear();
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerifiedWithTrace);
    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequestMutateDigest);
    g_mldsa_external_bridge_calls = 0;
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(g_mldsa_external_callback_trace, std::string{"M"});
    BOOST_CHECK_EQUAL(g_mldsa_external_bridge_calls, 0);

    // Keep bridge-ready verifier path for subsequent reject-path assertions.
    codequantum::SetMLDSA65ExternalBackendVerifierForTesting(ExternalBridgeVerified);
    codequantum::SetMLDSA65ExternalBackendRequestObserverForTesting(ObserveExternalRequest);

    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(std::vector<unsigned char>{}, pubkey_shape_valid, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, std::vector<unsigned char>{}, script_native)),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, pubkey_shape_valid, CScript())),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));

    // Error-priority contract for multi-invalid inputs:
    // parse/structural gates take precedence and all such combinations map to REJECTED.
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(std::vector<unsigned char>{}, std::vector<unsigned char>{}, CScript())),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(std::vector<unsigned char>{}, pubkey_shape_valid, CScript())),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(
                          codequantum::VerifyMLDSA65ExternalBackendAdapter(wrapped_sig_shape_valid, std::vector<unsigned char>{}, CScript())),
                      static_cast<unsigned char>(codequantum::MLDSA65BackendAdapterResult::REJECTED));
#else
    BOOST_CHECK(binding_before.is_available == nullptr);
    BOOST_CHECK(binding_before.verify == nullptr);
#endif

    codequantum::ResetMLDSA65ExternalBackendVerifierForTesting();
    codequantum::ResetMLDSA65ExternalBackendRequestObserverForTesting();
    codequantum::ResetMLDSA65ExternalBackendResultCodeVerifierForTesting();
}

BOOST_AUTO_TEST_CASE(code_quantum_mldsa_parser_contract_frozen)
{
    const std::vector<unsigned char> wrapped_sig_ok{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    const std::vector<unsigned char> wrapped_sig_alt_hashtype{
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_NONE),
    };
    const std::vector<unsigned char> wrapped_sig_bad_tag{
        0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    const std::vector<unsigned char> wrapped_sig_bad_len{
        0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> wrapped_sig_boundary72_low_s{
        0x30, 0x45, 0x02, 0x21,
        0x00, 0x80,
    };
    wrapped_sig_boundary72_low_s.insert(wrapped_sig_boundary72_low_s.end(), 31, 0x01);
    wrapped_sig_boundary72_low_s.push_back(0x02);
    wrapped_sig_boundary72_low_s.push_back(0x20);
    wrapped_sig_boundary72_low_s.insert(wrapped_sig_boundary72_low_s.end(), {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
    });
    wrapped_sig_boundary72_low_s.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    std::vector<unsigned char> wrapped_sig_bad_len_boundary = wrapped_sig_boundary72_low_s;
    wrapped_sig_bad_len_boundary[1] = 71;

    std::vector<unsigned char> wrapped_sig_bad_r_tag = wrapped_sig_ok;
    wrapped_sig_bad_r_tag[2] = 0x03;
    std::vector<unsigned char> wrapped_sig_bad_s_tag = wrapped_sig_ok;
    wrapped_sig_bad_s_tag[5] = 0x03;
    std::vector<unsigned char> wrapped_sig_zero_r_len = wrapped_sig_ok;
    wrapped_sig_zero_r_len[3] = 0x00;
    wrapped_sig_zero_r_len[1] = 0x05;
    std::vector<unsigned char> wrapped_sig_neg_r{
        0x30, 0x07, 0x02, 0x02, 0x80, 0x01, 0x02, 0x01,
        0x01, static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> wrapped_sig_redundant_r_zero{
        0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01,
        0x01, static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> wrapped_sig_high_s_32{
        0x30, 0x25, 0x02, 0x01, 0x01, 0x02, 0x20,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        static_cast<unsigned char>(SIGHASH_ALL),
    };
    std::vector<unsigned char> wrapped_sig_high_s_33{
        0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00,
        0x80,
    };
    wrapped_sig_high_s_33.insert(wrapped_sig_high_s_33.end(), 31, 0x00);
    wrapped_sig_high_s_33.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    codequantum::MLDSA65WrappedSigView wrapped_view{};
    codequantum::MLDSA65WrappedSigParseError wrapped_error = codequantum::MLDSA65WrappedSigParseError::OK;

    BOOST_CHECK(codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_ok));
    BOOST_CHECK(codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_alt_hashtype));
    BOOST_CHECK(codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_boundary72_low_s));
    BOOST_CHECK(codequantum::ParseMLDSA65WrappedSignature(wrapped_sig_ok, &wrapped_view));
    BOOST_CHECK_EQUAL(wrapped_view.der_sig_offset, 0U);
    BOOST_CHECK_EQUAL(wrapped_view.der_sig_size, 8U);
    BOOST_CHECK_EQUAL(wrapped_view.r_offset, 4U);
    BOOST_CHECK_EQUAL(wrapped_view.r_size, 1U);
    BOOST_CHECK(wrapped_view.r_is_minimally_encoded);
    BOOST_CHECK_EQUAL(wrapped_view.s_offset, 7U);
    BOOST_CHECK_EQUAL(wrapped_view.s_size, 1U);
    BOOST_CHECK(wrapped_view.s_is_minimally_encoded);
    BOOST_CHECK(wrapped_view.s_is_low);
    BOOST_CHECK_EQUAL(wrapped_view.sighash_offset, 8U);
    BOOST_CHECK_EQUAL(wrapped_view.sighash_type, static_cast<unsigned char>(SIGHASH_ALL));
    BOOST_CHECK(codequantum::ParseMLDSA65WrappedSignature(wrapped_sig_boundary72_low_s, &wrapped_view));
    BOOST_CHECK_EQUAL(wrapped_view.der_sig_offset, 0U);
    BOOST_CHECK_EQUAL(wrapped_view.der_sig_size, 71U);
    BOOST_CHECK_EQUAL(wrapped_view.r_offset, 4U);
    BOOST_CHECK_EQUAL(wrapped_view.r_size, 33U);
    BOOST_CHECK(wrapped_view.r_is_minimally_encoded);
    BOOST_CHECK_EQUAL(wrapped_view.s_offset, 39U);
    BOOST_CHECK_EQUAL(wrapped_view.s_size, 32U);
    BOOST_CHECK(wrapped_view.s_is_minimally_encoded);
    BOOST_CHECK(wrapped_view.s_is_low);
    BOOST_CHECK_EQUAL(wrapped_view.sighash_offset, 71U);
    BOOST_CHECK_EQUAL(wrapped_view.sighash_type, static_cast<unsigned char>(SIGHASH_ALL));
    BOOST_CHECK(codequantum::ParseMLDSA65WrappedSignature(wrapped_sig_alt_hashtype, &wrapped_view));
    BOOST_CHECK_EQUAL(wrapped_view.der_sig_offset, 0U);
    BOOST_CHECK_EQUAL(wrapped_view.der_sig_size, 8U);
    BOOST_CHECK_EQUAL(wrapped_view.r_offset, 4U);
    BOOST_CHECK_EQUAL(wrapped_view.r_size, 1U);
    BOOST_CHECK(wrapped_view.r_is_minimally_encoded);
    BOOST_CHECK_EQUAL(wrapped_view.s_offset, 7U);
    BOOST_CHECK_EQUAL(wrapped_view.s_size, 1U);
    BOOST_CHECK(wrapped_view.s_is_minimally_encoded);
    BOOST_CHECK(wrapped_view.s_is_low);
    BOOST_CHECK_EQUAL(wrapped_view.sighash_offset, 8U);
    BOOST_CHECK_EQUAL(wrapped_view.sighash_type, static_cast<unsigned char>(SIGHASH_NONE));
    BOOST_CHECK(codequantum::ParseMLDSA65WrappedSignature(wrapped_sig_ok, nullptr));
    BOOST_CHECK(codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig_ok, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::OK));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed({}, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::EMPTY_OR_OVERSIZE));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig_bad_tag, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::BAD_SEQUENCE_TAG));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig_bad_r_tag, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::BAD_R_TAG));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig_bad_s_tag, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::BAD_S_TAG));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig_redundant_r_zero, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::NON_MINIMAL_R));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed(wrapped_sig_high_s_32, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::HIGH_S));
    BOOST_CHECK(!codequantum::ParseMLDSA65WrappedSignatureDetailed(std::vector<unsigned char>{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00}, &wrapped_view, &wrapped_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(wrapped_error), static_cast<unsigned char>(codequantum::MLDSA65WrappedSigParseError::ZERO_HASHTYPE));

    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature({}));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(std::vector<unsigned char>{0x30, 0x00, static_cast<unsigned char>(SIGHASH_ALL)}));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(std::vector<unsigned char>(74, 0x01)));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_bad_tag));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_bad_len));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_bad_len_boundary));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_bad_r_tag));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_bad_s_tag));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_zero_r_len));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_neg_r));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_redundant_r_zero));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_high_s_32));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(wrapped_sig_high_s_33));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65WrappedSignature(std::vector<unsigned char>{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00}));

    std::vector<unsigned char> pubkey_compressed_02(33, 0x00);
    pubkey_compressed_02[0] = 0x02;
    std::vector<unsigned char> pubkey_compressed_03(33, 0x00);
    pubkey_compressed_03[0] = 0x03;
    std::vector<unsigned char> pubkey_uncompressed_04(65, 0x00);
    pubkey_uncompressed_04[0] = 0x04;

    codequantum::MLDSA65PubKeyView pubkey_view{};
    codequantum::MLDSA65PubKeyParseError pubkey_error = codequantum::MLDSA65PubKeyParseError::OK;

    BOOST_CHECK(codequantum::IsStructurallyValidMLDSA65PubKey(pubkey_compressed_02));
    BOOST_CHECK(codequantum::IsStructurallyValidMLDSA65PubKey(pubkey_compressed_03));
    BOOST_CHECK(codequantum::IsStructurallyValidMLDSA65PubKey(pubkey_uncompressed_04));
    BOOST_CHECK(codequantum::ParseMLDSA65PubKey(pubkey_compressed_02, &pubkey_view));
    BOOST_CHECK(pubkey_view.is_compressed);
    BOOST_CHECK_EQUAL(pubkey_view.payload_offset, 1U);
    BOOST_CHECK_EQUAL(pubkey_view.payload_size, 32U);
    BOOST_CHECK_EQUAL(pubkey_view.prefix, 0x02);
    BOOST_CHECK(codequantum::ParseMLDSA65PubKey(pubkey_compressed_03, &pubkey_view));
    BOOST_CHECK(pubkey_view.is_compressed);
    BOOST_CHECK_EQUAL(pubkey_view.payload_offset, 1U);
    BOOST_CHECK_EQUAL(pubkey_view.payload_size, 32U);
    BOOST_CHECK_EQUAL(pubkey_view.prefix, 0x03);
    BOOST_CHECK(codequantum::ParseMLDSA65PubKey(pubkey_uncompressed_04, &pubkey_view));
    BOOST_CHECK(!pubkey_view.is_compressed);
    BOOST_CHECK_EQUAL(pubkey_view.payload_offset, 1U);
    BOOST_CHECK_EQUAL(pubkey_view.payload_size, 64U);
    BOOST_CHECK_EQUAL(pubkey_view.prefix, 0x04);
    BOOST_CHECK(codequantum::ParseMLDSA65PubKey(pubkey_compressed_03, nullptr));
    BOOST_CHECK(codequantum::ParseMLDSA65PubKeyDetailed(pubkey_compressed_02, &pubkey_view, &pubkey_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(pubkey_error), static_cast<unsigned char>(codequantum::MLDSA65PubKeyParseError::OK));
    BOOST_CHECK(!codequantum::ParseMLDSA65PubKeyDetailed({}, &pubkey_view, &pubkey_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(pubkey_error), static_cast<unsigned char>(codequantum::MLDSA65PubKeyParseError::EMPTY));
    BOOST_CHECK(!codequantum::ParseMLDSA65PubKeyDetailed(std::vector<unsigned char>(66, 0x02), &pubkey_view, &pubkey_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(pubkey_error), static_cast<unsigned char>(codequantum::MLDSA65PubKeyParseError::OVERSIZE));
    BOOST_CHECK(!codequantum::ParseMLDSA65PubKeyDetailed(std::vector<unsigned char>(33, 0x00), &pubkey_view, &pubkey_error));
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(pubkey_error), static_cast<unsigned char>(codequantum::MLDSA65PubKeyParseError::INVALID_FORMAT));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65PubKey({}));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65PubKey(std::vector<unsigned char>(66, 0x02)));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65PubKey(std::vector<unsigned char>(33, 0x00)));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65PubKey(std::vector<unsigned char>(65, 0x00)));
    BOOST_CHECK(!codequantum::IsStructurallyValidMLDSA65PubKey(std::vector<unsigned char>(33, 0x04)));
}

BOOST_AUTO_TEST_CASE(code_quantum_budget_boundaries_frozen)
{
    const KeyData keys;
    const CScript script_pub_key = CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG;
    const CScriptWitness empty_witness;
    constexpr unsigned int cq_flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_FJARCODE_OPCODES;

    const CTransaction tx_credit{BuildCreditingTransaction(script_pub_key, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), tx_credit);
    const uint256 legacy_sighash = SignatureHash(script_pub_key, tx_spend, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    std::vector<unsigned char> wrapped_sig73;
    std::vector<unsigned char> r;
    std::vector<unsigned char> s;
    uint32_t iter = 0;
    do {
        keys.key1C.Sign(legacy_sighash, wrapped_sig73, false, iter++);
        if ((33 == 33) != (wrapped_sig73[5 + wrapped_sig73[3]] == 33)) {
            NegateSignatureS(wrapped_sig73);
        }
        r = std::vector<unsigned char>(wrapped_sig73.begin() + 4, wrapped_sig73.begin() + 4 + wrapped_sig73[3]);
        s = std::vector<unsigned char>(wrapped_sig73.begin() + 6 + wrapped_sig73[3], wrapped_sig73.begin() + 6 + wrapped_sig73[3] + wrapped_sig73[5 + wrapped_sig73[3]]);
    } while (r.size() != 33 || s.size() != 33);
    wrapped_sig73.push_back(SIGHASH_ALL);

    const auto make_envelope = [](uint8_t mode, uint8_t algorithm, const std::vector<unsigned char>& wrapped_sig) {
        std::vector<unsigned char> envelope;
        envelope.reserve(6 + wrapped_sig.size());
        envelope.push_back('C');
        envelope.push_back('Q');
        envelope.push_back(1);
        envelope.push_back(mode);
        envelope.push_back(algorithm);
        envelope.push_back(static_cast<unsigned char>(wrapped_sig.size()));
        envelope.insert(envelope.end(), wrapped_sig.begin(), wrapped_sig.end());
        return envelope;
    };

    BOOST_REQUIRE_EQUAL(wrapped_sig73.size(), 73U);
    const std::vector<unsigned char> envelope_max_budget = make_envelope(/*mode=*/0, /*algorithm=*/0, wrapped_sig73);
    BOOST_REQUIRE_EQUAL(envelope_max_budget.size(), 79U);

    DoTest(script_pub_key,
        CScript() << envelope_max_budget,
        empty_witness,
        cq_flags,
        "Code Quantum envelope max wrapped signature and total size accepted",
        SCRIPT_ERR_OK);

    std::vector<unsigned char> wrapped_sig74 = wrapped_sig73;
    wrapped_sig74.push_back(0x00);
    BOOST_REQUIRE_EQUAL(wrapped_sig74.size(), 74U);

    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, wrapped_sig74),
        empty_witness,
        cq_flags,
        "Code Quantum envelope wrapped signature size over budget rejected",
        SCRIPT_ERR_CODE_QUANTUM_NONCANONICAL_ENCODING);
}

BOOST_AUTO_TEST_CASE(code_quantum_pubkey_and_stack_budget_frozen)
{
    const KeyData keys;
    const CScriptWitness empty_witness;
    constexpr unsigned int cq_flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_FJARCODE_OPCODES;

    const CScript normal_script_pub_key = CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG;
    const CTransaction tx_credit{BuildCreditingTransaction(normal_script_pub_key, 0)};
    CMutableTransaction tx_spend = BuildSpendingTransaction(CScript(), CScriptWitness(), tx_credit);
    const uint256 legacy_sighash = SignatureHash(normal_script_pub_key, tx_spend, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    std::vector<unsigned char> wrapped_sig;
    keys.key1C.Sign(legacy_sighash, wrapped_sig);
    wrapped_sig.push_back(SIGHASH_ALL);

    const auto make_envelope = [](uint8_t mode, uint8_t algorithm, const std::vector<unsigned char>& payload) {
        std::vector<unsigned char> envelope;
        envelope.reserve(6 + payload.size());
        envelope.push_back('C');
        envelope.push_back('Q');
        envelope.push_back(1);
        envelope.push_back(mode);
        envelope.push_back(algorithm);
        envelope.push_back(static_cast<unsigned char>(payload.size()));
        envelope.insert(envelope.end(), payload.begin(), payload.end());
        return envelope;
    };

    // Pubkey-size budget: valid CQ signature envelope + oversized pubkey push must fail.
    std::vector<unsigned char> oversized_pubkey(66, 0x02);
    const CScript oversized_pubkey_script = CScript() << oversized_pubkey << OP_CHECKSIG;
    DoTest(oversized_pubkey_script,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, wrapped_sig),
        empty_witness,
        cq_flags,
        "Code Quantum oversized pubkey rejected by budget",
        SCRIPT_ERR_PUBKEYTYPE);

    // Stack-push-total budget: 79-byte envelope + 66-byte pubkey exceeds limit.
    std::vector<unsigned char> max_envelope_payload(73, 0x00);
    const std::vector<unsigned char> max_envelope = make_envelope(/*mode=*/0, /*algorithm=*/0, max_envelope_payload);
    BOOST_REQUIRE_EQUAL(max_envelope.size(), 79U);
    DoTest(oversized_pubkey_script,
        CScript() << max_envelope,
        empty_witness,
        cq_flags,
        "Code Quantum stack push total budget enforced",
        SCRIPT_ERR_PUSH_SIZE);

    // Verify-cost budget: 73-byte wrapped signature + 65-byte uncompressed pubkey exceeds 106.
    const CScript uncompressed_pubkey_script = CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG;
    DoTest(uncompressed_pubkey_script,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, wrapped_sig),
        empty_witness,
        cq_flags,
        "Code Quantum verify cost budget enforced",
        SCRIPT_ERR_OP_COUNT);
}

BOOST_AUTO_TEST_CASE(code_quantum_reject_precedence_frozen)
{
    const KeyData keys;
    const CScript script_pub_key = CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG;
    const CScriptWitness empty_witness;
    constexpr unsigned int cq_flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_FJARCODE_OPCODES;

    const auto make_envelope = [](uint8_t mode, uint8_t algorithm, const std::vector<unsigned char>& wrapped_sig) {
        std::vector<unsigned char> envelope;
        envelope.reserve(6 + wrapped_sig.size());
        envelope.push_back('C');
        envelope.push_back('Q');
        envelope.push_back(1);
        envelope.push_back(mode);
        envelope.push_back(algorithm);
        envelope.push_back(static_cast<unsigned char>(wrapped_sig.size()));
        envelope.insert(envelope.end(), wrapped_sig.begin(), wrapped_sig.end());
        return envelope;
    };

    // Decode failures must win over later mode/algo/missing-sig checks.
    DoTest(script_pub_key,
        CScript() << ParseHex("435101ff0001"),
        empty_witness,
        cq_flags,
        "Code Quantum reject precedence decode before mode",
        SCRIPT_ERR_CODE_QUANTUM_NONCANONICAL_ENCODING);

    // Unsupported mode must win over missing-required-signature.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/255, /*algorithm=*/0, /*wrapped_sig=*/{}),
        empty_witness,
        cq_flags,
        "Code Quantum reject precedence mode before missing-signature",
        SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_MODE);

    // Unsupported algorithm must win over missing-required-signature.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/3, /*wrapped_sig=*/{}),
        empty_witness,
        cq_flags,
        "Code Quantum reject precedence algorithm before missing-signature",
        SCRIPT_ERR_CODE_QUANTUM_UNSUPPORTED_ALGORITHM_ID);

    // Missing-required-signature must win before wrapped-signature DER checks.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, /*wrapped_sig=*/{}),
        empty_witness,
        cq_flags,
        "Code Quantum reject precedence missing-signature before DER validation",
        SCRIPT_ERR_CODE_QUANTUM_MISSING_REQUIRED_SIG);

    // Wrapped-signature DER noncanonicality must win before hashtype/policy checks.
    DoTest(script_pub_key,
        CScript() << make_envelope(/*mode=*/0, /*algorithm=*/0, std::vector<unsigned char>{0x01}),
        empty_witness,
        cq_flags,
        "Code Quantum reject precedence DER validation before hashtype",
        SCRIPT_ERR_CODE_QUANTUM_NONCANONICAL_ENCODING);
}

BOOST_AUTO_TEST_CASE(bip341_keypath_test_vectors)
{
    UniValue tests;
    tests.read(json_tests::bip341_wallet_vectors);

    const auto& vectors = tests["keyPathSpending"];

    for (const auto& vec : vectors.getValues()) {
        auto txhex = ParseHex(vec["given"]["rawUnsignedTx"].get_str());
        CMutableTransaction tx;
        SpanReader{txhex} >> TX_WITH_WITNESS(tx);
        std::vector<CTxOut> utxos;
        for (const auto& utxo_spent : vec["given"]["utxosSpent"].getValues()) {
            auto script_bytes = ParseHex(utxo_spent["scriptPubKey"].get_str());
            CScript script{script_bytes.begin(), script_bytes.end()};
            CAmount amount{utxo_spent["amountSats"].getInt<int>()};
            utxos.emplace_back(amount, script);
        }

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{utxos}, true);

        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_amounts_single_hash), vec["intermediary"]["hashAmounts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_outputs_single_hash), vec["intermediary"]["hashOutputs"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_prevouts_single_hash), vec["intermediary"]["hashPrevouts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_scripts_single_hash), vec["intermediary"]["hashScriptPubkeys"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_sequences_single_hash), vec["intermediary"]["hashSequences"].get_str());

        for (const auto& input : vec["inputSpending"].getValues()) {
            int txinpos = input["given"]["txinIndex"].getInt<int>();
            int hashtype = input["given"]["hashType"].getInt<int>();

            // Load key.
            auto privkey = ParseHex(input["given"]["internalPrivkey"].get_str());
            CKey key;
            key.Set(privkey.begin(), privkey.end(), true);

            // Load Merkle root.
            uint256 merkle_root;
            if (!input["given"]["merkleRoot"].isNull()) {
                merkle_root = uint256{ParseHex(input["given"]["merkleRoot"].get_str())};
            }

            // Compute and verify (internal) public key.
            XOnlyPubKey pubkey{key.GetPubKey()};
            BOOST_CHECK_EQUAL(HexStr(pubkey), input["intermediary"]["internalPubkey"].get_str());

            // Sign and verify signature.
            FlatSigningProvider provider;
            provider.keys[key.GetPubKey().GetID()] = key;
            MutableTransactionSignatureCreator creator(tx, txinpos, utxos[txinpos].nValue, &txdata, hashtype);
            std::vector<unsigned char> signature;
            BOOST_CHECK(creator.CreateSchnorrSig(provider, signature, pubkey, nullptr, &merkle_root, SigVersion::TAPROOT));
            BOOST_CHECK_EQUAL(HexStr(signature), input["expected"]["witness"][0].get_str());

            // We can't observe the tweak used inside the signing logic, so verify by recomputing it.
            BOOST_CHECK_EQUAL(HexStr(pubkey.ComputeTapTweakHash(merkle_root.IsNull() ? nullptr : &merkle_root)), input["intermediary"]["tweak"].get_str());

            // We can't observe the sighash used inside the signing logic, so verify by recomputing it.
            ScriptExecutionData sed;
            sed.m_annex_init = true;
            sed.m_annex_present = false;
            uint256 sighash;
            BOOST_CHECK(SignatureHashSchnorr(sighash, sed, tx, txinpos, hashtype, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
            BOOST_CHECK_EQUAL(HexStr(sighash), input["intermediary"]["sigHash"].get_str());

            // To verify the sigmsg, hash the expected sigmsg, and compare it with the (expected) sighash.
            BOOST_CHECK_EQUAL(HexStr((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{ParseHex(input["intermediary"]["sigMsg"].get_str())}).GetSHA256()), input["intermediary"]["sigHash"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(compute_tapbranch)
{
    constexpr uint256 hash1{"8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7"};
    constexpr uint256 hash2{"f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a"};
    constexpr uint256 result{"a64c5b7b943315f9b805d7a7296bedfcfd08919270a1f7a1466e98f8693d8cd9"};
    BOOST_CHECK_EQUAL(ComputeTapbranchHash(hash1, hash2), result);
}

BOOST_AUTO_TEST_CASE(compute_tapleaf)
{
    constexpr uint8_t script[6] = {'f','o','o','b','a','r'};
    constexpr uint256 tlc0{"edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06"};
    constexpr uint256 tlc2{"8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a"};

    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc0, std::span(script)), tlc0);
    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc2, std::span(script)), tlc2);
}

BOOST_AUTO_TEST_SUITE_END()
