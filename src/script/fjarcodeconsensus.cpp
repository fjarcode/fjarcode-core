// Copyright (c) 2009-2026 Satoshi Nakamoto
// Copyright (c) 2009-2026 The Bitcoin Core developers
// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/fjarcodeconsensus.h>

#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <serialize.h>

#include <cstddef>
#include <cstring>
#include <exception>
#include <span>
#include <vector>

namespace {

class TxInputStream
{
public:
    TxInputStream(const unsigned char* tx_to, size_t tx_to_len) : m_data(tx_to), m_remaining(tx_to_len) {}

    void read(std::span<std::byte> dst)
    {
        if (dst.size() > m_remaining) {
            throw std::ios_base::failure(std::string(__func__) + ": end of data");
        }
        if (dst.data() == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");
        }
        if (m_data == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");
        }

        std::memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    TxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

private:
    const unsigned char* m_data;
    size_t m_remaining;
};

inline int set_error(fjarcodeconsensus_error* ret, fjarcodeconsensus_error serror)
{
    if (ret) *ret = serror;
    return 0;
}

} // namespace

static bool verify_flags(unsigned int flags)
{
    if ((flags & ~(fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_ALL)) != 0) {
        return false;
    }
    // Mirror script/interpreter flag preconditions so callers get API errors
    // instead of debug-assert aborts for invalid combinations.
    if ((flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS) != 0 &&
        (flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH) == 0) {
        return false;
    }
    if ((flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT) != 0 &&
        (flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS) == 0) {
        return false;
    }
    return true;
}

static int verify_script(const unsigned char* script_pub_key,
                         unsigned int script_pub_key_len,
                         CAmount amount,
                         const unsigned char* tx_to,
                         unsigned int tx_to_len,
                         const UTXO* spent_outputs,
                         unsigned int spent_outputs_len,
                         unsigned int n_in,
                         unsigned int flags,
                         fjarcodeconsensus_error* err)
{
    if (!verify_flags(flags)) return set_error(err, fjarcodeconsensus_ERR_INVALID_FLAGS);

    if ((flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT) && spent_outputs == nullptr) {
        return set_error(err, fjarcodeconsensus_ERR_SPENT_OUTPUTS_REQUIRED);
    }

    try {
        TxInputStream stream(tx_to, tx_to_len);
        CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

        std::vector<CTxOut> spent;
        if (spent_outputs != nullptr) {
            if (spent_outputs_len != tx.vin.size()) {
                return set_error(err, fjarcodeconsensus_ERR_SPENT_OUTPUTS_MISMATCH);
            }
            spent.reserve(spent_outputs_len);
            for (size_t i = 0; i < spent_outputs_len; ++i) {
                const CScript spk{spent_outputs[i].scriptPubKey, spent_outputs[i].scriptPubKey + spent_outputs[i].scriptPubKeySize};
                spent.emplace_back(CAmount{spent_outputs[i].value}, spk);
            }
        }

        if (n_in >= tx.vin.size()) return set_error(err, fjarcodeconsensus_ERR_TX_INDEX);
        if (GetSerializeSize(TX_WITH_WITNESS(tx)) != tx_to_len) return set_error(err, fjarcodeconsensus_ERR_TX_SIZE_MISMATCH);

        set_error(err, fjarcodeconsensus_ERR_OK);

        PrecomputedTransactionData tx_data(tx);
        if (spent_outputs != nullptr && (flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT)) {
            tx_data.Init(tx, std::move(spent));
        }

        return VerifyScript(tx.vin[n_in].scriptSig,
                            CScript(script_pub_key, script_pub_key + script_pub_key_len),
                            &tx.vin[n_in].scriptWitness,
                            flags,
                            TransactionSignatureChecker(&tx, n_in, amount, tx_data, MissingDataBehavior::FAIL),
                            nullptr);
    } catch (const std::exception&) {
        return set_error(err, fjarcodeconsensus_ERR_TX_DESERIALIZE);
    }
}

int fjarcodeconsensus_verify_script_with_spent_outputs(const unsigned char* script_pub_key,
                                                       unsigned int script_pub_key_len,
                                                       int64_t amount,
                                                       const unsigned char* tx_to,
                                                       unsigned int tx_to_len,
                                                       const UTXO* spent_outputs,
                                                       unsigned int spent_outputs_len,
                                                       unsigned int n_in,
                                                       unsigned int flags,
                                                       fjarcodeconsensus_error* err)
{
    return verify_script(script_pub_key, script_pub_key_len, CAmount{amount}, tx_to, tx_to_len,
                         spent_outputs, spent_outputs_len, n_in, flags, err);
}

int fjarcodeconsensus_verify_script_with_amount(const unsigned char* script_pub_key,
                                                unsigned int script_pub_key_len,
                                                int64_t amount,
                                                const unsigned char* tx_to,
                                                unsigned int tx_to_len,
                                                unsigned int n_in,
                                                unsigned int flags,
                                                fjarcodeconsensus_error* err)
{
    return verify_script(script_pub_key, script_pub_key_len, CAmount{amount}, tx_to, tx_to_len,
                         nullptr, 0, n_in, flags, err);
}

int fjarcodeconsensus_verify_script(const unsigned char* script_pub_key,
                                    unsigned int script_pub_key_len,
                                    const unsigned char* tx_to,
                                    unsigned int tx_to_len,
                                    unsigned int n_in,
                                    unsigned int flags,
                                    fjarcodeconsensus_error* err)
{
    if (flags & fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS) {
        return set_error(err, fjarcodeconsensus_ERR_AMOUNT_REQUIRED);
    }

    return verify_script(script_pub_key, script_pub_key_len, CAmount{0}, tx_to, tx_to_len,
                         nullptr, 0, n_in, flags, err);
}

unsigned int fjarcodeconsensus_version()
{
    return FJARCODECONSENSUS_API_VER;
}
