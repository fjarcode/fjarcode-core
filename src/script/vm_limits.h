// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_VM_LIMITS_H
#define BITCOIN_SCRIPT_VM_LIMITS_H

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace vm_limits {

static constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE_LEGACY = 520;
static constexpr int MAX_OPS_PER_SCRIPT_LEGACY = 201;

namespace may2025 {

static constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE = 10000;
static constexpr unsigned int OPCODE_COST = 100u;
static constexpr unsigned int MAX_CONDITIONAL_STACK_DEPTH = 100u;
static constexpr unsigned int SIG_CHECK_COST_FACTOR = 26'000u;

namespace detail {
static constexpr unsigned int HASH_ITER_BONUS_FOR_NONSTD_TXNS = 7u;
static constexpr unsigned int OP_COST_BUDGET_PER_INPUT_BYTE = 800u;
static constexpr unsigned int HASH_COST_PENALTY_FOR_STD_TXNS = 3u;
static constexpr unsigned int HASH_BLOCK_SIZE = 64u;
static constexpr unsigned int INPUT_SCRIPT_SIZE_FIXED_CREDIT = 41u;

inline constexpr int64_t GetInputHashItersLimit(bool standard, uint64_t script_sig_size) noexcept
{
	const auto factor = standard ? 1u : HASH_ITER_BONUS_FOR_NONSTD_TXNS;
	const int64_t ret = ((script_sig_size + INPUT_SCRIPT_SIZE_FIXED_CREDIT) * factor) / 2u;
	assert(ret >= 0);
	return ret;
}

inline constexpr int64_t GetInputOpCostLimit(uint64_t script_sig_size) noexcept
{
	const int64_t ret = (script_sig_size + INPUT_SCRIPT_SIZE_FIXED_CREDIT) * OP_COST_BUDGET_PER_INPUT_BYTE;
	assert(ret >= 0);
	return ret;
}
} // namespace detail

inline constexpr int64_t GetHashIterOpCostFactor(bool standard) noexcept
{
	return standard ? detail::HASH_BLOCK_SIZE * detail::HASH_COST_PENALTY_FOR_STD_TXNS : detail::HASH_BLOCK_SIZE;
}

inline constexpr int64_t CalcHashIters(uint32_t message_length, bool is_two_round_hash_op) noexcept
{
	return is_two_round_hash_op + 1u + ((static_cast<uint64_t>(message_length) + 8u) / detail::HASH_BLOCK_SIZE);
}

class ScriptLimits {
	int64_t m_op_cost_limit;
	int64_t m_hash_iters_limit;

public:
	ScriptLimits(bool standard, uint64_t script_sig_size)
		: m_op_cost_limit{detail::GetInputOpCostLimit(script_sig_size)},
		  m_hash_iters_limit{detail::GetInputHashItersLimit(standard, script_sig_size)}
	{
	}

	int64_t GetOpCostLimit() const { return m_op_cost_limit; }
	int64_t GetHashItersLimit() const { return m_hash_iters_limit; }
};

} // namespace may2025

} // namespace vm_limits

#endif // BITCOIN_SCRIPT_VM_LIMITS_H
