#pragma once

#include "vnm_direct_native_backend_p.h"

#include <memory>

namespace vnm::filesystem_observation::detail {

struct native_drain_counts_t
{
    size_t detail_bytes = 0;
    size_t peak_detail_bytes = 0;
    uint64_t batches = 0;
    uint64_t kernel_overflows = 0;
    uint64_t decoder_budget_losses = 0;
    uint64_t handoff_overflows = 0;
};

// Native completion/rearm never calls registry maintenance or consumers. Detail
// retained between those owners is bounded; losing it retains a registration-wide
// reconciliation obligation until the registry takes the handoff.
class Direct_native_drain
{
public:
    explicit Direct_native_drain(size_t maximum_detail_bytes = 4 * 1024 * 1024);
    ~Direct_native_drain();
    Direct_native_drain(const Direct_native_drain&) = delete;
    Direct_native_drain& operator=(const Direct_native_drain&) = delete;

    bool arm(uint64_t registration, const QString& directory, QString& error);
    void retire(uint64_t registration);
#ifdef Q_OS_WIN
    bool retirement_pending(uint64_t registration) const;
#endif
    bool identity_matches(uint64_t registration) const;
    Native_wait_result wait(std::chrono::milliseconds timeout);
    void wake();

    size_t allocated_registrations() const;
    size_t allocated_bytes() const;
    native_drain_counts_t resource_counts() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace vnm::filesystem_observation::detail
