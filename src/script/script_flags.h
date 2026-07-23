// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_FLAGS_H
#define BITCOIN_SCRIPT_SCRIPT_FLAGS_H

#include <script/interpreter.h>

#include <cstdint>

// Compatibility extension flags not present in upstream interpreter flag enum.
static constexpr uint32_t SCRIPT_ENABLE_SIGHASH_FORKID = (1U << 21);
static constexpr uint32_t SCRIPT_ENABLE_FJARCODE_OPCODES = (1U << 23);
// Unused placeholders in this migration stage; kept as 0 to avoid accidental activation
// when callers pass complemented/unsanitized test flag sets.
static constexpr uint32_t SCRIPT_DISALLOW_SEGWIT_RECOVERY = 0;
static constexpr uint32_t SCRIPT_ENABLE_SCHNORR_MULTISIG = 0;
static constexpr uint32_t SCRIPT_VERIFY_INPUT_SIGCHECKS = 0;
static constexpr uint32_t SCRIPT_ENFORCE_SIGCHECKS = 0;
static constexpr uint32_t SCRIPT_64_BIT_INTEGERS = 0;
static constexpr uint32_t SCRIPT_NATIVE_INTROSPECTION = 0;
static constexpr uint32_t SCRIPT_ENABLE_P2SH_32 = 0;
static constexpr uint32_t SCRIPT_ENABLE_VM_LIMITS = (1U << 28);
static constexpr uint32_t SCRIPT_ENABLE_TOKENS = (1U << 29);
static constexpr uint32_t SCRIPT_ENABLE_MAY2025 = (1U << 30);
static constexpr uint32_t SCRIPT_VM_LIMITS_STANDARD = (1U << 31);
// Reserved for a future activation stage. Keep disabled in this migration step
// to avoid accidental activation under complemented/unsanitized flag sets.
static constexpr uint32_t SCRIPT_ENABLE_MAY2026 = 0;

static constexpr uint32_t SCRIPT_COMPAT_USED_FLAGS =
	SCRIPT_ENABLE_SIGHASH_FORKID |
	SCRIPT_ENABLE_FJARCODE_OPCODES |
	SCRIPT_ENABLE_VM_LIMITS |
	SCRIPT_ENABLE_TOKENS |
	SCRIPT_ENABLE_MAY2025 |
	SCRIPT_VM_LIMITS_STANDARD;

static_assert((SCRIPT_COMPAT_USED_FLAGS & (SCRIPT_VERIFY_END_MARKER - 1U)) == 0,
	"Compat script flags must not overlap upstream SCRIPT_VERIFY_* bit range");

inline constexpr bool IsExplicitCompatFlagsContext(uint32_t flags)
{
	const uint32_t known_flags = (SCRIPT_VERIFY_END_MARKER - 1U) | SCRIPT_COMPAT_USED_FLAGS;
	return (flags & ~known_flags) == 0;
}

inline constexpr bool IsVmLimitsEnabled(uint32_t flags)
{
	// Keep MAY2025 as a compatibility umbrella while VM limits has its own flag bit.
	return (flags & (SCRIPT_ENABLE_VM_LIMITS | SCRIPT_ENABLE_MAY2025)) != 0;
}

#endif // BITCOIN_SCRIPT_SCRIPT_FLAGS_H
