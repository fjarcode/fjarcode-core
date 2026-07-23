// Copyright (c) 2026 The FJARCODE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_METRICS_H
#define BITCOIN_SCRIPT_SCRIPT_METRICS_H

#include <script/script_flags.h>
#include <script/vm_limits.h>

#include <cstdint>
#include <optional>

class ScriptExecutionMetrics {
    int m_sig_checks{0};
    int64_t m_op_cost{0};
    int64_t m_hash_digest_iterations{0};
    std::optional<vm_limits::may2025::ScriptLimits> m_script_limits;

    static bool IsVmLimitsStandard(uint32_t script_flags)
    {
        return (script_flags & SCRIPT_VM_LIMITS_STANDARD) != 0;
    }

public:
    ScriptExecutionMetrics() noexcept = default;

    int GetSigChecks() const { return m_sig_checks; }
    int64_t GetBaseOpCost() const { return m_op_cost; }
    int64_t GetHashDigestIterations() const { return m_hash_digest_iterations; }

    int64_t GetCompositeOpCost(uint32_t script_flags) const
    {
        const int64_t hash_iter_cost = vm_limits::may2025::GetHashIterOpCostFactor(IsVmLimitsStandard(script_flags));
        return m_op_cost + m_hash_digest_iterations * hash_iter_cost + static_cast<int64_t>(m_sig_checks) * vm_limits::may2025::SIG_CHECK_COST_FACTOR;
    }

    void TallyOp(uint32_t cost)
    {
        m_op_cost += static_cast<int64_t>(cost);
    }

    void TallyPushOp(uint32_t stack_item_length)
    {
        m_op_cost += static_cast<int64_t>(stack_item_length);
    }

    void TallyHashOp(uint32_t message_length, bool is_two_round_hash_op)
    {
        m_hash_digest_iterations += vm_limits::may2025::CalcHashIters(message_length, is_two_round_hash_op);
    }

    void TallySigChecks(int n_checks)
    {
        m_sig_checks += n_checks;
    }

    bool HasValidScriptLimits() const
    {
        return m_script_limits.has_value();
    }

    void SetScriptLimits(uint32_t script_flags, uint64_t script_sig_size)
    {
        m_script_limits.emplace(IsVmLimitsStandard(script_flags), script_sig_size);
    }

    bool IsOverOpCostLimit(uint32_t script_flags) const
    {
        return m_script_limits && GetCompositeOpCost(script_flags) > m_script_limits->GetOpCostLimit();
    }

    bool IsOverHashItersLimit() const
    {
        return m_script_limits && GetHashDigestIterations() > m_script_limits->GetHashItersLimit();
    }
};

inline bool UseVmLimitsStandardCosting(uint32_t flags)
{
    return (flags & SCRIPT_VM_LIMITS_STANDARD) != 0;
}

#endif // BITCOIN_SCRIPT_SCRIPT_METRICS_H
