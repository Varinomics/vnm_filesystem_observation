#pragma once

#include "vnm_filesystem_native_event.h"

#include <QList>
#include <QString>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace vnm::filesystem_observation::detail {

struct Direct_change
{
    uint64_t registration = 0;
    Native_batch batch;
    bool coverage_lost = false;
    bool rearm_required = false;
};

struct Native_wait_result
{
    QList<Direct_change> changes;
    // Retirement can release native custody without any remaining file detail.
    bool capacity_changed = false;
};

struct native_loss_counts_t
{
    uint64_t kernel_overflows = 0;
    uint64_t decoder_budget_losses = 0;
};

// One native drain calls wait(); maintenance serializes arm/retire and identity
// checks concurrently with it. Native cancellation retains its buffers until the
// OS has finished using them. Destruction follows joining the drain.
class Direct_native_backend
{
public:
    Direct_native_backend();
    ~Direct_native_backend();
    Direct_native_backend(const Direct_native_backend&) = delete;
    Direct_native_backend& operator=(const Direct_native_backend&) = delete;

    bool arm(uint64_t registration, const QString& directory, QString& error);
    void retire(uint64_t registration);
#ifdef Q_OS_WIN
    // Resume a completed request whose notification format needs a new handle.
    // Only maintenance performs the reopening and identity probes.
    bool resume(uint64_t registration, QString& error);
    // True until the retired operation's completion releases its native storage.
    bool retirement_pending(uint64_t registration) const;
#endif
    bool identity_matches(uint64_t registration) const;
    // max() requests an unbounded wait, subject to the backend's control-wake
    // recovery bound. An ordinary timeout carries no maintenance work.
    Native_wait_result wait(std::chrono::milliseconds timeout);
    void wake();

    // Includes native operations whose cancellation completion is outstanding.
    size_t allocated_registrations() const;
    size_t allocated_bytes() const;
    native_loss_counts_t loss_counts() const;
    static size_t registration_bytes(const QString& directory);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace vnm::filesystem_observation::detail
