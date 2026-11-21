#pragma once

#include "vnm_filesystem_native_watcher.h"

#include <QSettings>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace vnm::filesystem_observation {

struct Configuration
{
    std::chrono::milliseconds general_interval{4000};
    std::chrono::milliseconds document_interval{2000};

    // Invalid persisted values are reported, rather than silently changing policy.
    static Configuration from_settings(const QSettings& settings);
    void validate() const;
};

struct capture_t
{
    uint64_t subscription_id = 0;
    uint64_t generation = 0;
    uint64_t event_sequence = 0;
    uint64_t coverage_sequence = 0;
};

struct Batch
{
    capture_t capture;
    QList<Event> events;
    QStringList scopes;
    bool all_interests = false;
    bool rescan_required = false;
    QString diagnostic;
    // False for initial admission, native events, loss and unknown causes.
    // Any such work merged into a filter replan retains full source readback.
    bool consumer_reconciliation_only = false;
    // Initial admission, possibly combined with a continuous filter replan,
    // still requires this subscriber's readback. Native detail, loss, unknown
    // causes and detail promotion clear this through the retained obligation.
    bool initial_admission_only = false;
};

class Completion
{
public:
    Completion() = default;
    explicit Completion(std::function<void()> release);
    void complete();

private:
    struct State;
    std::shared_ptr<State> m_state;
};

struct Delivery
{
    Batch batch;
    Completion completion;
    std::shared_ptr<std::atomic_bool> active;

    bool valid() const noexcept;
};

// submit() only transfers bounded work; it must never execute consumer work or wait
// for a receiver. Each channel belongs to one subscription.
class Delivery_channel
{
public:
    virtual ~Delivery_channel() = default;
    virtual void submit(Delivery delivery) = 0;
    virtual void cancel() = 0;
};

class Wait_channel final : public Delivery_channel
{
public:
    Wait_channel();
    ~Wait_channel() override;
    std::optional<Delivery> wait(std::chrono::milliseconds timeout);
    void submit(Delivery delivery) override;
    void cancel() override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

struct Subscription_options
{
    QList<Watch_spec> directories;
    QStringList exact_files;
    Watch_mode mode = Watch_mode::RECURSIVE;
    std::shared_ptr<path_name::Policy_epoch> policy_epoch;
    std::chrono::milliseconds interval{4000};
    uint32_t event_kinds = 15;
    // A bounded, nonblocking semantic predicate. Git/acquisition belongs to the receiver.
    std::function<bool(const Event&)> classifier;
    // Selects subdirectories on bounded expansion workers outside native-state
    // locks. It must not block on Git or consumer acquisition; retirement drains
    // running calls before the callback's captured state may be destroyed.
    Native_watcher::Directory_filter directory_filter;
};

enum class Workload_admission
{
    BOUNDED,
    UNCAPPED
};

struct limits_t
{
    size_t subscriptions = 65536;
    size_t retained_events = 256;
    size_t retained_characters = 65536;
    size_t retained_scopes = 32;
    // Bounds both interest spelling text and each owned epoch's retained parent prefixes.
    size_t interest_characters = 1048576;
    // Registrations share one dispatch/arming worker. Cancellation still
    // owns native buffers until completion and consumes these same budgets.
    size_t native_registrations = 4096;
    size_t native_bytes = 64 * 1024 * 1024;
    size_t scan_workers = 1;
    size_t plan_bytes = 8 * 1024 * 1024;
    // Uncapped interests/plans/native ownership grow until allocation or the OS
    // refuses them. Event detail bounds and scan concurrency still apply.
    Workload_admission workload_admission = Workload_admission::BOUNDED;
};

struct statistics_t
{
    uint64_t dispatches = 0;
    uint64_t promotions = 0;
    size_t retained_events = 0;
    size_t outstanding = 0;
    size_t subscriptions = 0;
    size_t control_threads = 0;
    // Native counts describe published registrations; these expose lifecycle work
    // whose native resources are still being armed or joined.
    size_t pending_registrations = 0;
    size_t retiring_groups = 0;
    size_t policy_cache_entries = 0;
    size_t policy_cache_characters = 0;
};

namespace detail { struct Service_state; }

class Subscription
{
public:
    Subscription() = default;
    ~Subscription();
    Subscription(Subscription&& other) noexcept;
    Subscription& operator=(Subscription&& other) noexcept;
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;

    // Once reset() returns, the classifier and directory filter are neither running
    // nor called again, and the service has released them on the resetting thread.
    // It waits for a call running on another thread, so do not reset while holding a
    // lock such a callback takes. A callback may reset its own subscription; that
    // returns into the callback, no further call starts, and the callables are then
    // released later on whichever service or native thread drops the last reference.
    void reset();
    void update_interval(std::chrono::milliseconds interval);
    std::chrono::milliseconds effective_interval() const;
    bool acknowledge(capture_t capture);
    bool rescan_required() const;
    bool covers_directory(const QString& path) const;
    // Current per-scope registration state, independent of retained captures.
    Coverage_status coverage_status(const QString& path) const;
    uint64_t coverage_revision(const QString& path) const;
    void request_rescan(const QString& reason);
    // Replace the immutable eligibility snapshot of an already filtered recursive
    // interest. Establishes reconciliation before returning; outstanding delivery
    // and cooldown ownership are retained. Coverage is incomplete until the new
    // generation arms. Reset also drains callbacks from retired generations.
    bool replace_directory_filter(Native_watcher::Directory_filter filter);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    void set_coverage_for_tests(const QString& path, bool covered);
#endif

private:
    friend class Service;
    Subscription(std::shared_ptr<detail::Service_state> state, uint64_t id);
    std::shared_ptr<detail::Service_state> m_state;
    uint64_t m_id = 0;
};

// Own this once at the process composition root and pass the shared handle to consumers.
// Neither scheduler shutdown nor completion waits for the receiver's event loop.
class Service
{
public:
    explicit Service(limits_t limits = {});
    ~Service();
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    Subscription subscribe(Subscription_options options, std::shared_ptr<Delivery_channel> channel);
    statistics_t statistics() const;
    Resource_counts resource_counts() const;
    void shutdown();

    // Deterministic scheduler gates use the same ingestion and deadline paths as native input.
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    QStringList armed_directories_for_tests() const;
    QStringList covered_logical_directories_for_tests() const;
    // Injects native failure for an existing logical directory even while its path is absent.
    bool set_directory_available_for_tests(const QString& path, bool available);
    void ingest_for_tests(const Subscription& subscription, const Native_batch& batch);
    void use_manual_clock_for_tests();
    void advance_clock_for_tests(std::chrono::milliseconds elapsed);
#endif

private:
    std::shared_ptr<detail::Service_state> m_state;
};

} // namespace vnm::filesystem_observation
