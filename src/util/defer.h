// Copyright (c) 2021 The Bitcoin developers
// Copyright (c) 2025 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FJARCODE_UTIL_DEFER_H
#define FJARCODE_UTIL_DEFER_H

#include <utility>

/// Leverage RAII to run a functor at scope end
template <typename Func>
struct Defer {
    Func func;
    Defer(Func && f) : func(std::move(f)) {}
    ~Defer() { func(); }
};

#endif // FJARCODE_UTIL_DEFER_H
