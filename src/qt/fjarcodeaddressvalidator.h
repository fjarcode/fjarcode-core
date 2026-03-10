// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Fjarcode developers
// Copyright (c) 2025 The FJARCODE developers
// Forked from Bitcoin Core version 0.27.0
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FJARCODE_QT_FJARCODEADDRESSVALIDATOR_H
#define FJARCODE_QT_FJARCODEADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class FjarcodeAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit FjarcodeAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** Fjarcode address widget validator, checks for a valid FJAR address.
 */
class FjarcodeAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit FjarcodeAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

using FJARCODEAddressEntryValidator = FjarcodeAddressEntryValidator;
using FJARCODEAddressCheckValidator = FjarcodeAddressCheckValidator;

#endif // FJARCODE_QT_FJARCODEADDRESSVALIDATOR_H
