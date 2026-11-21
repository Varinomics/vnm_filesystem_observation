#include "vnm_direct_native_drain_p.h"
#include "vnm_native_event_decode_p.h"
#include "vnm_native_test_hooks_p.h"

#include <algorithm>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <utility>

namespace vnm::filesystem_observation::detail {
namespace {

size_t event_bytes(const Event& event)
{
    return sizeof(Event) + size_t(event.path.size() + event.old_path.size()) * sizeof(QChar);
}

} // namespace

struct Direct_native_drain::Impl
{
    struct Pending
    {
        Direct_change change;
        size_t bytes = 0;
        bool overflow = false;
    };

    explicit Impl(size_t maximum_detail_bytes)
    :
        m_maximum_bytes(maximum_detail_bytes)
    {}

    void retain(Direct_change change)
    {
        if (!m_active.contains(change.registration)) {
            return;
        }
        ++m_counts.batches;
        auto& pending = m_changes[change.registration];
        auto& retained = pending.change;
        auto& batch = retained.batch;
        if (retained.registration == 0) {
            retained.registration = change.registration;
            batch.root = change.batch.root;
            batch.scope = change.batch.scope;
        }
        retained.coverage_lost |= change.coverage_lost;
        retained.rearm_required |= change.rearm_required;
        if (change.batch.rescan_required) {
            const bool complete = (!batch.rescan_required || batch.rescan_event_paths_complete) &&
                change.batch.rescan_event_paths_complete;
            mark_native_rescan(batch, change.batch.diagnostic, change.batch.reason);
            batch.rescan_event_paths_complete = complete;
        }
        if (change.coverage_lost) {
            batch.reason = change.batch.reason;
            batch.diagnostic = change.batch.diagnostic;
        }
        if (pending.overflow) {
            return;
        }
        for (auto& event : change.batch.events) {
            if (batch.events.contains(event)) {
                continue;
            }
            const size_t bytes = event_bytes(event);
            if (batch.events.size() >= 256 || bytes > m_maximum_bytes - m_counts.detail_bytes) {
                m_counts.detail_bytes -= pending.bytes;
                pending.bytes = 0;
                pending.overflow = true;
                batch.events = {};
                mark_native_rescan(batch, QStringLiteral("Native handoff detail budget exceeded"),
                    Native_reason::QUEUE_OVERFLOW);
                ++m_counts.handoff_overflows;
                break;
            }
            batch.events.append(std::move(event));
            pending.bytes += bytes;
            m_counts.detail_bytes += bytes;
            m_counts.peak_detail_bytes = std::max(m_counts.peak_detail_bytes, m_counts.detail_bytes);
        }
    }

    void run()
    {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::native_drain_threads;
#endif
        for (;;) {
            auto incoming = m_backend.wait(std::chrono::milliseconds::max());
            const std::lock_guard lock(m_mutex);
            if (m_stopped) {
                break;
            }
            for (auto& change : incoming.changes) {
                retain(std::move(change));
            }
            m_capacity_changed |= incoming.capacity_changed;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            ++native_test_hooks::native_wait_returns;
            if (incoming.capacity_changed) {
                ++native_test_hooks::native_capacity_changes;
            }
#endif
            if (!m_changes.empty() || m_capacity_changed) {
                m_ready.notify_one();
            }
        }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        --native_test_hooks::native_drain_threads;
#endif
    }

    Direct_native_backend m_backend;
    const size_t m_maximum_bytes;
    mutable std::mutex m_mutex;
    std::condition_variable m_ready;
    std::set<uint64_t> m_active;
    std::map<uint64_t, Pending> m_changes;
    native_drain_counts_t m_counts;
    bool m_stopped          = false;
    bool m_wake_pending     = false;
    bool m_capacity_changed = false;
    std::thread m_worker;
};

Direct_native_drain::Direct_native_drain(size_t maximum_detail_bytes)
:
    m_impl(std::make_unique<Impl>(maximum_detail_bytes))
{
    m_impl->m_worker = std::thread([state = m_impl.get()] { state->run(); });
}

Direct_native_drain::~Direct_native_drain()
{
    {
        const std::lock_guard lock(m_impl->m_mutex);
        m_impl->m_stopped = true;
    }
    m_impl->m_backend.wake();
    m_impl->m_worker.join();
}

bool Direct_native_drain::arm(uint64_t registration, const QString& directory, QString& error)
{
    {
        const std::lock_guard lock(m_impl->m_mutex);
        m_impl->m_active.insert(registration);
    }
    if (m_impl->m_backend.arm(registration, directory, error)) {
        m_impl->m_backend.wake();
        return true;
    }
    retire(registration);
    return false;
}

void Direct_native_drain::retire(uint64_t registration)
{
    {
        const std::lock_guard lock(m_impl->m_mutex);
        m_impl->m_active.erase(registration);
        const auto found = m_impl->m_changes.find(registration);
        if (found != m_impl->m_changes.end()) {
            m_impl->m_counts.detail_bytes -= found->second.bytes;
            m_impl->m_changes.erase(found);
        }
    }
    m_impl->m_backend.retire(registration);
}

#ifdef Q_OS_WIN
bool Direct_native_drain::retirement_pending(uint64_t registration) const
{
    return m_impl->m_backend.retirement_pending(registration);
}
#endif

bool Direct_native_drain::identity_matches(uint64_t registration) const
{
    return m_impl->m_backend.identity_matches(registration);
}

Native_wait_result Direct_native_drain::wait(std::chrono::milliseconds timeout)
{
    Native_wait_result result;
    {
        std::unique_lock lock(m_impl->m_mutex);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::native_handoff_waits;
#endif
        const auto ready = [&] {
            return !m_impl->m_changes.empty() || m_impl->m_wake_pending || m_impl->m_capacity_changed;
        };
        if (timeout == std::chrono::milliseconds::max()) {
            m_impl->m_ready.wait(lock, ready);
        }
        else {
            m_impl->m_ready.wait_for(lock, timeout, ready);
        }
        m_impl->m_wake_pending = false;
        result.capacity_changed = std::exchange(m_impl->m_capacity_changed, false);
        for (auto& [registration, pending] : m_impl->m_changes) {
            result.changes.append(std::move(pending.change));
        }
        m_impl->m_changes.clear();
        m_impl->m_counts.detail_bytes = 0;
    }
    // Filesystem identity probes belong to maintenance, never the native drain.
    // An identity lost after completion cannot lend its detail to a replacement.
    for (auto& change : result.changes) {
#ifdef Q_OS_WIN
        if (change.rearm_required) {
            QString error;
            if (!m_impl->m_backend.resume(change.registration, error)) {
                change.coverage_lost = true;
                mark_native_rescan(change.batch, error, Native_reason::REGISTRATION_FAILED);
                change.batch.reason = Native_reason::REGISTRATION_FAILED;
                change.batch.diagnostic = error;
            }
            change.rearm_required = false;
        }
#endif
        if (!change.coverage_lost && !identity_matches(change.registration)) {
            change.coverage_lost = true;
            mark_native_rescan(change.batch, QStringLiteral("Watched directory identity changed"),
                Native_reason::COVERAGE_CHANGED);
            retire(change.registration);
        }
        if (change.coverage_lost) {
            change.batch.events.clear();
            change.batch.rescan_event_paths_complete = false;
        }
    }
    return result;
}

void Direct_native_drain::wake()
{
    {
        const std::lock_guard lock(m_impl->m_mutex);
        m_impl->m_wake_pending = true;
    }
    m_impl->m_ready.notify_one();
    m_impl->m_backend.wake();
}

size_t Direct_native_drain::allocated_registrations() const
{
    return m_impl->m_backend.allocated_registrations();
}

size_t Direct_native_drain::allocated_bytes() const
{
    return m_impl->m_backend.allocated_bytes();
}

native_drain_counts_t Direct_native_drain::resource_counts() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    auto counts = m_impl->m_counts;
    const auto loss = m_impl->m_backend.loss_counts();
    counts.kernel_overflows = loss.kernel_overflows;
    counts.decoder_budget_losses = loss.decoder_budget_losses;
    return counts;
}

} // namespace vnm::filesystem_observation::detail
