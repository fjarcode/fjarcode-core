// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGHASHTYPE_H
#define BITCOIN_SCRIPT_SIGHASHTYPE_H

#include <script/interpreter.h>
#include <serialize.h>

#include <cstdint>

static constexpr uint8_t SIGHASH_UTXOS = 0x20;
static constexpr uint8_t SIGHASH_FORKID = 0x40;

enum class BaseSigHashType : uint8_t {
    UNSUPPORTED = 0,
    ALL = SIGHASH_ALL,
    NONE = SIGHASH_NONE,
    SINGLE = SIGHASH_SINGLE,
};

class SigHashType {
private:
    uint32_t m_sighash;

public:
    SigHashType() : m_sighash(SIGHASH_ALL) {}
    explicit SigHashType(uint32_t sighash) : m_sighash(sighash) {}

    SigHashType withBaseType(BaseSigHashType base_type) const
    {
        return SigHashType((m_sighash & ~0x1fU) | static_cast<uint32_t>(base_type));
    }

    SigHashType withFork(bool fork = true) const
    {
        return SigHashType((m_sighash & ~SIGHASH_FORKID) | (fork ? SIGHASH_FORKID : 0));
    }

    SigHashType withAnyoneCanPay(bool anyone_can_pay = true) const
    {
        return SigHashType((m_sighash & ~SIGHASH_ANYONECANPAY) | (anyone_can_pay ? SIGHASH_ANYONECANPAY : 0));
    }

    SigHashType withUtxos(bool utxos = true) const
    {
        return SigHashType((m_sighash & ~SIGHASH_UTXOS) | (utxos ? SIGHASH_UTXOS : 0));
    }

    BaseSigHashType getBaseType() const
    {
        return static_cast<BaseSigHashType>(m_sighash & 0x1fU);
    }

    bool hasFork() const { return (m_sighash & SIGHASH_FORKID) != 0; }
    bool hasAnyoneCanPay() const { return (m_sighash & SIGHASH_ANYONECANPAY) != 0; }
    bool hasUtxos() const { return (m_sighash & SIGHASH_UTXOS) != 0; }

    bool isDefined() const
    {
        const uint8_t valid_flags = SIGHASH_FORKID | SIGHASH_ANYONECANPAY | SIGHASH_UTXOS;
        const auto base_type = static_cast<BaseSigHashType>(m_sighash & ~valid_flags);
        return base_type >= BaseSigHashType::ALL && base_type <= BaseSigHashType::SINGLE;
    }

    uint32_t getRawSigHashType() const { return m_sighash; }

    template <typename Stream>
    void Serialize(Stream& s) const { ::Serialize(s, getRawSigHashType()); }

    template <typename Stream>
    void Unserialize(Stream& s) { ::Unserialize(s, m_sighash); }

    friend bool operator==(const SigHashType& a, const SigHashType& b)
    {
        return a.m_sighash == b.m_sighash;
    }

    friend bool operator!=(const SigHashType& a, const SigHashType& b)
    {
        return !(a == b);
    }
};

#endif // BITCOIN_SCRIPT_SIGHASHTYPE_H
