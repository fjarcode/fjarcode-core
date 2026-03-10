// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Fjarcode developers
// Copyright (c) 2025 The FJARCODE developers
// Forked from Bitcoin Core version 0.27.0
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FJARCODE_SCRIPT_FJARCODECONSENSUS_H
#define FJARCODE_SCRIPT_FJARCODECONSENSUS_H

#include <stdint.h>

#if defined(BUILD_FJARCODE_INTERNAL) && defined(HAVE_CONFIG_H)
#include <config/fjarcode-config.h>
  #if defined(_WIN32)
    #if defined(HAVE_DLLEXPORT_ATTRIBUTE)
      #define EXPORT_SYMBOL __declspec(dllexport)
    #else
      #define EXPORT_SYMBOL
    #endif
  #elif defined(HAVE_DEFAULT_VISIBILITY_ATTRIBUTE)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBFJARCODECONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FJARCODECONSENSUS_API_VER 2

typedef enum fjarcodeconsensus_error_t
{
  fjarcodeconsensus_ERR_OK = 0,
  fjarcodeconsensus_ERR_TX_INDEX,
  fjarcodeconsensus_ERR_TX_SIZE_MISMATCH,
  fjarcodeconsensus_ERR_TX_DESERIALIZE,
  fjarcodeconsensus_ERR_AMOUNT_REQUIRED,
  fjarcodeconsensus_ERR_INVALID_FLAGS,
  fjarcodeconsensus_ERR_SPENT_OUTPUTS_REQUIRED,
  fjarcodeconsensus_ERR_SPENT_OUTPUTS_MISMATCH
} fjarcodeconsensus_error;

/** Script verification flags */
enum
{
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), // enforce NULLDUMMY (BIP147)
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), // enable CHECKSEQUENCEVERIFY (BIP112)
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), // enable WITNESS (BIP141)
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT             = (1U << 17), // enable TAPROOT (BIPs 341 & 342)
    fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_ALL                 = fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_P2SH | fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_DERSIG |
                                   fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY | fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                   fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_WITNESS |
                                   fjarcodeconsensus_SCRIPT_FLAGS_VERIFY_TAPROOT
};

typedef struct {
    const unsigned char *scriptPubKey;
    unsigned int scriptPubKeySize;
    int64_t value;
} UTXO;

/// Returns 1 if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
/// If not nullptr, err will contain an error/success code for the operation
EXPORT_SYMBOL int fjarcodeconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                                 const unsigned char *txTo        , unsigned int txToLen,
                                                 unsigned int nIn, unsigned int flags, fjarcodeconsensus_error* err);

EXPORT_SYMBOL int fjarcodeconsensus_verify_script_with_amount(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, fjarcodeconsensus_error* err);

EXPORT_SYMBOL int fjarcodeconsensus_verify_script_with_spent_outputs(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen, int64_t amount,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    const UTXO *spentOutputs, unsigned int spentOutputsLen,
                                    unsigned int nIn, unsigned int flags, fjarcodeconsensus_error* err);

EXPORT_SYMBOL unsigned int fjarcodeconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // FJARCODE_SCRIPT_FJARCODECONSENSUS_H
