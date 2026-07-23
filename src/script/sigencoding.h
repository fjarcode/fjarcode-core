// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGENCODING_H
#define BITCOIN_SCRIPT_SIGENCODING_H

#include <script/container_types.h>
#include <script/script_error.h>
#include <script/sighashtype.h>

inline SigHashType GetHashType(const ByteView& sig)
{
    if (sig.empty()) return SigHashType{0};
    return SigHashType{sig.back()};
}

bool CheckDataSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror);
bool CheckTransactionSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror);
bool CheckTransactionECDSASignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror);
bool CheckTransactionSchnorrSignatureEncoding(const ByteView& sig, uint32_t flags, ScriptError* serror);
bool CheckPubKeyEncoding(const ByteView& pubkey, uint32_t flags, ScriptError* serror);

#endif // BITCOIN_SCRIPT_SIGENCODING_H
