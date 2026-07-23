// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sigencoding.h>

#include <pubkey.h>
#include <script/script_flags.h>

#include <vector>

namespace {

inline bool set_error(ScriptError* ret, const ScriptError serror)
{
    if (ret) *ret = serror;
    return false;
}

bool IsValidDERSignatureEncoding(const ByteView& sig)
{
    if (sig.size() < 8 || sig.size() > 72) return false;
    if (sig[0] != 0x30) return false;
    if (sig[1] != sig.size() - 2) return false;
    if (sig[2] != 0x02) return false;

    const uint32_t len_r = sig[3];
    if (len_r == 0) return false;
    if (sig[4] & 0x80) return false;
    if (len_r > (sig.size() - 7)) return false;
    if (len_r > 1 && sig[4] == 0x00 && !(sig[5] & 0x80)) return false;

    const uint32_t start_s = len_r + 4;
    if (sig[start_s] != 0x02) return false;

    const uint32_t len_s = sig[start_s + 1];
    if (len_s == 0) return false;
    if (sig[start_s + 2] & 0x80) return false;
    if (size_t(start_s + len_s + 2) != sig.size()) return false;
    if (len_s > 1 && sig[start_s + 2] == 0x00 && !(sig[start_s + 3] & 0x80)) return false;

    return true;
}

bool IsSchnorrSig(const ByteView& sig)
{
    return sig.size() == 64;
}

bool CheckRawECDSASignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    if (IsSchnorrSig(sig)) return set_error(serror, SCRIPT_ERR_SIG_DER);

    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 &&
        !IsValidDERSignatureEncoding(sig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }

    if ((flags & SCRIPT_VERIFY_LOW_S) != 0) {
        std::vector<unsigned char> sig_vec(sig.begin(), sig.end());
        if (!CPubKey::CheckLowS(sig_vec)) {
            return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
        }
    }

    return true;
}

bool CheckRawSchnorrSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    (void)flags;
    if (IsSchnorrSig(sig)) return true;
    return set_error(serror, SCRIPT_ERR_SIG_DER);
}

bool CheckRawSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    if (IsSchnorrSig(sig)) return true;
    return CheckRawECDSASignatureEncoding(sig, flags, serror);
}

bool CheckSighashEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    if ((flags & SCRIPT_VERIFY_STRICTENC) == 0) return true;

    const auto hash_type = GetHashType(sig);
    if (!hash_type.isDefined()) return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);

    const bool compat_context = IsExplicitCompatFlagsContext(flags);
    const bool uses_forkid = hash_type.hasFork();
    const bool forkid_enabled = compat_context && (flags & SCRIPT_ENABLE_SIGHASH_FORKID) != 0;
    if (!forkid_enabled && uses_forkid) return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    // Legacy signatures without FORKID are still accepted on this chain for
    // historical compatibility. FORKID remains available and enforced where
    // transaction-level rules require it.

    if (hash_type.hasUtxos()) {
        const bool tokens_enabled = compat_context && (flags & SCRIPT_ENABLE_TOKENS) != 0;
        if (!tokens_enabled || !uses_forkid || hash_type.hasAnyoneCanPay()) {
            return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
        }
    }

    return true;
}

template <typename RawCheck>
bool CheckTransactionSigEncodingImpl(const ByteView& sig, uint32_t flags, ScriptError* serror, RawCheck&& raw_check)
{
    if (sig.empty()) return true;

    if (!raw_check(sig.first(sig.size() - 1), flags, serror)) return false;
    return CheckSighashEncoding(sig, flags, serror);
}

bool IsCompressedOrUncompressedPubKey(const ByteView& pubkey)
{
    switch (pubkey.size()) {
    case CPubKey::COMPRESSED_SIZE:
        return pubkey[0] == 0x02 || pubkey[0] == 0x03;
    case CPubKey::SIZE:
        return pubkey[0] == 0x04;
    default:
        return false;
    }
}

} // namespace

bool CheckDataSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    if (sig.empty()) return true;
    return CheckRawSignatureEncoding(sig, flags, serror);
}

bool CheckTransactionSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    return CheckTransactionSigEncodingImpl(sig, flags, serror,
        [](const ByteView& raw_sig, uint32_t raw_flags, ScriptError* raw_error) {
            return CheckRawSignatureEncoding(raw_sig, raw_flags, raw_error);
        });
}

bool CheckTransactionECDSASignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    return CheckTransactionSigEncodingImpl(sig, flags, serror,
        [](const ByteView& raw_sig, uint32_t raw_flags, ScriptError* raw_error) {
            return CheckRawECDSASignatureEncoding(raw_sig, raw_flags, raw_error);
        });
}

bool CheckTransactionSchnorrSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror)
{
    return CheckTransactionSigEncodingImpl(sig, flags, serror,
        [](const ByteView& raw_sig, uint32_t raw_flags, ScriptError* raw_error) {
            return CheckRawSchnorrSignatureEncoding(raw_sig, raw_flags, raw_error);
        });
}

bool CheckPubKeyEncoding(const ByteView& pubkey, uint32_t flags, ScriptError* serror)
{
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(pubkey)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    return true;
}
