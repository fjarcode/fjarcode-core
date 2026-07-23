// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <key.h>
#include <key_io.h>
#include <cashaddr.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);
    CKey privkey;
    CTxDestination destination;
    SelectParams(ChainType::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        const std::vector<std::byte> exp_payload{ParseHex<std::byte>(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        bool try_case_flip = metadata.find_value("tryCaseFlip").isNull() ? false : metadata.find_value("tryCaseFlip").get_bool();
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            // Must be valid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(privkey.IsValid(), "!IsValid:" + strTest);
            BOOST_CHECK_MESSAGE(privkey.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(std::ranges::equal(privkey, exp_payload), "key mismatch:" + strTest);

            // Private key must be invalid public key
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid privkey as pubkey:" + strTest);
        } else {
            // Must be valid public key
            destination = DecodeDestination(exp_base58string);
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_address_string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            BOOST_CHECK_MESSAGE(EncodeSecret(key) == exp_address_string, "result mismatch: " + strTest);
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            std::string generated_address = EncodeDestination(dest);

            const CTxDestination expected_dest = DecodeDestination(exp_address_string);
            const CTxDestination generated_dest = DecodeDestination(generated_address);
            BOOST_CHECK_MESSAGE(IsValidDestination(expected_dest), "invalid expected address vector: " + strTest);
            BOOST_CHECK_MESSAGE(IsValidDestination(generated_dest), "invalid generated address: " + strTest);
            BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(expected_dest)), HexStr(exp_script));
            BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(generated_dest)), HexStr(exp_script));
        }
    }

    SelectParams(ChainType::MAIN);
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

BOOST_AUTO_TEST_CASE(key_io_code_quantum_cashaddr_roundtrip)
{
    SelectParams(ChainType::MAIN);

    uint256 raw_hash;
    for (size_t i = 0; i < raw_hash.size(); ++i) {
        raw_hash.begin()[i] = static_cast<unsigned char>(i);
    }

    const QuantumHash quantum_hash{raw_hash};
    const CTxDestination quantum_dest{quantum_hash};
    const std::string encoded = EncodeDestination(quantum_dest);

    BOOST_CHECK(!encoded.empty());
    BOOST_CHECK_MESSAGE(encoded.rfind("fjarcode:", 0) == 0, "Quantum cashaddr must use fjarcode prefix");

    const CTxDestination decoded = DecodeDestination(encoded);
    BOOST_CHECK(IsValidDestination(decoded));
    BOOST_CHECK(decoded == quantum_dest);

    const CScript script = GetScriptForDestination(decoded);
    std::vector<std::vector<unsigned char>> all_solutions;
    const TxoutType which_type = Solver(script, all_solutions);
    BOOST_CHECK_EQUAL(which_type, TxoutType::SCRIPTHASH32);
}

BOOST_AUTO_TEST_CASE(key_io_fjarcode_known_cashaddr_vectors)
{
    SelectParams(ChainType::MAIN);

    const std::string valid_addr{"fjarcode:qq55ygm0ae7hjes30r3kk305rtywsjl8253htzkjrj"};
    const CTxDestination valid_dest = DecodeDestination(valid_addr);
    BOOST_CHECK_MESSAGE(IsValidDestination(valid_dest), "Known-good FJAR CashAddr must decode");

    const CScript valid_script = GetScriptForDestination(valid_dest);
    BOOST_CHECK_EQUAL(HexStr(valid_script), "76a9142942236fee7d79661178e36b45f41ac8e84be75588ac");

    const std::string invalid_addr{"fjarcode:qzj9gkyvrh9rmgnpftrd23jyva86jeumtc4m2gud2k"};
    const CTxDestination invalid_dest = DecodeDestination(invalid_addr);
    BOOST_CHECK_MESSAGE(!IsValidDestination(invalid_dest), "Known-bad FJAR CashAddr must be rejected");
}

BOOST_AUTO_TEST_CASE(key_io_quantum_native_legacy_compatibility_contract)
{
    SelectParams(ChainType::MAIN);

    uint160 raw_hash;
    for (size_t i = 0; i < raw_hash.size(); ++i) {
        raw_hash.begin()[i] = static_cast<unsigned char>(0x10 + i);
    }
    const PKHash p2pkh{raw_hash};
    const CTxDestination dest{p2pkh};

    const std::string legacy_base58 = EncodeDestination(dest, AddressFormat::LEGACY);
    const std::string standard_cashaddr = EncodeDestination(dest, AddressFormat::CASHADDR);
    const std::string quantum_format_cashaddr = EncodeDestination(dest, AddressFormat::QUANTUM);

    BOOST_CHECK(!legacy_base58.empty());
    BOOST_CHECK(!standard_cashaddr.empty());
    BOOST_CHECK(!quantum_format_cashaddr.empty());

    // Native quantum format must preserve legacy cashaddr type-0x00 behavior for P2PKH.
    BOOST_CHECK_EQUAL(quantum_format_cashaddr, standard_cashaddr);
    BOOST_CHECK(DecodeDestination(legacy_base58) == dest);
    BOOST_CHECK(DecodeDestination(standard_cashaddr) == dest);
    BOOST_CHECK(DecodeDestination(quantum_format_cashaddr) == dest);

    const auto decoded = cashaddr::Decode(quantum_format_cashaddr, Params().CashAddrPrefix());
    BOOST_CHECK(!decoded.first.empty());
    BOOST_CHECK(!decoded.second.empty());
    const auto unpacked = cashaddr::UnpackAddrData(decoded.second);
    BOOST_CHECK_EQUAL(unpacked.first, static_cast<uint8_t>(0));
    BOOST_CHECK_EQUAL(unpacked.second.size(), static_cast<size_t>(20));
}

BOOST_AUTO_TEST_SUITE_END()
