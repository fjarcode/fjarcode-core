// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/fjarcodeconsensus.h>

#include <script/script.h>
#include <streams.h>
#include <test/util/transaction_utils.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

namespace {

struct TxPair {
    CTransaction credit;
    CTransaction spend;
};

TxPair BuildEqualSpend()
{
    CScript script_pub_key;
    CScript script_sig;
    CScriptWitness witness;

    // scriptSig pushes 1,1; scriptPubKey checks equality -> true
    script_sig << OP_1 << OP_1;
    script_pub_key << OP_EQUAL;

    CTransaction credit{BuildCreditingTransaction(script_pub_key, 1)};
    CTransaction spend{BuildSpendingTransaction(script_sig, witness, credit)};
    return {credit, spend};
}

DataStream SerializeTxWithWitness(const CTransaction& tx)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(tx);
    return stream;
}

} // namespace

BOOST_AUTO_TEST_SUITE(fjarcodeconsensus_tests)

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_returns_true)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        UCharCast(stream.data()),
        stream.size(),
        0,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NONE,
        &err);

    BOOST_CHECK_EQUAL(result, 1);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_OK);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_with_amount_returns_true)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const unsigned int witness_flags =
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS;
    const int result = fjarcodeconsensus_verify_script_with_amount(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        0,
        witness_flags,
        &err);

    BOOST_CHECK_EQUAL(result, 1);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_OK);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_with_spent_outputs_returns_true)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    const unsigned int taproot_flag =
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT;
    const unsigned char* spk_ptr = tx_pair.credit.vout[0].scriptPubKey.data();
    const unsigned int spk_size = tx_pair.credit.vout[0].scriptPubKey.size();
    const UTXO spent_outputs[] = {
        {spk_ptr, spk_size, tx_pair.credit.vout[0].nValue},
    };

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script_with_spent_outputs(
        spk_ptr,
        spk_size,
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        spent_outputs,
        1,
        0,
        taproot_flag,
        &err);

    BOOST_CHECK_EQUAL(result, 1);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_OK);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_tx_index_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        UCharCast(stream.data()),
        stream.size(),
        1,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NONE,
        &err);

    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_TX_INDEX);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_tx_size_mismatch_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        UCharCast(stream.data()),
        stream.size() * 2,
        0,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NONE,
        &err);

    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_TX_SIZE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_tx_deserialize_err)
{
    DataStream stream;
    stream << uint32_t{0xffffffff};

    const CScript script_pub_key = CScript() << OP_EQUAL;

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script(
        script_pub_key.data(),
        script_pub_key.size(),
        UCharCast(stream.data()),
        stream.size(),
        0,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NONE,
        &err);

    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_TX_DESERIALIZE);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_amount_required_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        UCharCast(stream.data()),
        stream.size(),
        0,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS,
        &err);

    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_AMOUNT_REQUIRED);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_invalid_flags_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        UCharCast(stream.data()),
        stream.size(),
        0,
        (1U << 3),
        &err);

    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_INVALID_FLAGS);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_invalid_flag_combinations_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    const unsigned char* spk_ptr = tx_pair.credit.vout[0].scriptPubKey.data();
    const unsigned int spk_size = tx_pair.credit.vout[0].scriptPubKey.size();

    fjarcodeconsensus_error err;

    // WITNESS without P2SH is invalid for script verification flags.
    int result = fjarcodeconsensus_verify_script_with_amount(
        spk_ptr,
        spk_size,
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        0,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS,
        &err);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_INVALID_FLAGS);

    // TAPROOT without WITNESS is also invalid.
    result = fjarcodeconsensus_verify_script_with_spent_outputs(
        spk_ptr,
        spk_size,
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        nullptr,
        0,
        0,
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT,
        &err);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_INVALID_FLAGS);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_spent_outputs_required_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    fjarcodeconsensus_error err;
    const unsigned int taproot_flag =
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT;

    int result = fjarcodeconsensus_verify_script_with_spent_outputs(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        nullptr,
        0,
        0,
        taproot_flag,
        &err);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_SPENT_OUTPUTS_REQUIRED);

    result = fjarcodeconsensus_verify_script_with_amount(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        0,
        taproot_flag,
        &err);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_SPENT_OUTPUTS_REQUIRED);

    result = fjarcodeconsensus_verify_script(
        tx_pair.credit.vout[0].scriptPubKey.data(),
        tx_pair.credit.vout[0].scriptPubKey.size(),
        UCharCast(stream.data()),
        stream.size(),
        0,
        taproot_flag,
        &err);
    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_AMOUNT_REQUIRED);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_verify_script_spent_outputs_mismatch_err)
{
    const TxPair tx_pair{BuildEqualSpend()};
    DataStream stream{SerializeTxWithWitness(tx_pair.spend)};

    const unsigned int taproot_flag =
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS |
        fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT;
    const unsigned char* spk_ptr = tx_pair.credit.vout[0].scriptPubKey.data();
    const unsigned int spk_size = tx_pair.credit.vout[0].scriptPubKey.size();

    // tx_pair.spend has 1 input, so spent_outputs_len=2 must fail.
    const UTXO spent_outputs[] = {
        {spk_ptr, spk_size, tx_pair.credit.vout[0].nValue},
        {spk_ptr, spk_size, tx_pair.credit.vout[0].nValue},
    };

    fjarcodeconsensus_error err;
    const int result = fjarcodeconsensus_verify_script_with_spent_outputs(
        spk_ptr,
        spk_size,
        tx_pair.credit.vout[0].nValue,
        UCharCast(stream.data()),
        stream.size(),
        spent_outputs,
        2,
        0,
        taproot_flag,
        &err);

    BOOST_CHECK_EQUAL(result, 0);
    BOOST_CHECK_EQUAL(err, fjarcodeconsensus_ERR_SPENT_OUTPUTS_MISMATCH);
}

BOOST_AUTO_TEST_CASE(fjarcodeconsensus_version_matches_constant)
{
    BOOST_CHECK_EQUAL(fjarcodeconsensus_version(), FJARCODECONSENSUS_API_VER);
}

BOOST_AUTO_TEST_SUITE_END()
