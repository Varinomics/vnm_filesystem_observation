#include "vnm_filesystem_observation.h"
#include "vnm_filesystem_observation_variant.h"
#include "vnm_direct_registry_p.h"
#include "vnm_native_test_hooks_p.h"

#include <QFileInfo>
#include <QDir>
#include <QMap>
#include <QScopeGuard>

#include <algorithm>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <set>
#include <thread>
#include <utility>
#include <vector>

VNM_FILESYSTEM_OBSERVATION_REFERENCE_VARIANT(service)

namespace vnm::filesystem_observation {
namespace {

using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::milliseconds;

void validate_interval(Milliseconds interval)
{
    if (interval.count() < 1 || interval > std::chrono::hours(24)) {
        throw std::invalid_argument("Observation interval must be between 1 ms and 24 hours");
    }
}

Milliseconds read_interval(const QSettings& settings, const QString& key, Milliseconds fallback)
{
    bool converted = false;
    const auto value = settings.value(key, qlonglong(fallback.count())).toLongLong(&converted);
    if (!converted) {
        throw std::invalid_argument((QStringLiteral("Invalid observation setting: ") + key).toStdString());
    }
    const Milliseconds interval(value);
    validate_interval(interval);
    return interval;
}

bool has_work(const Batch& batch)
{
    return batch.rescan_required || !batch.events.isEmpty();
}

struct Registration_projection
{
    QList<Watch_spec> directories;
    QList<path_name::Key> keys;
};

Registration_projection project_registrations(
    const QList<Watch_spec>& directories, const path_name::Policy_epoch& policy)
{
    Registration_projection projection;
    for (const auto& directory : directories) {
        auto key = policy.key(directory.path);
        const auto index = projection.keys.indexOf(key);
        if (index >= 0) {
            auto& depth = projection.directories[index].maximum_depth;
            depth = std::max(depth, directory.maximum_depth);
        }
        else {
            projection.directories.append(directory);
            projection.keys.append(std::move(key));
        }
    }
    return projection;
}

} // namespace

Configuration Configuration::from_settings(const QSettings& settings)
{
    Configuration result;
    result.general_interval = read_interval(
        settings, QStringLiteral("observation/general_interval_ms"), result.general_interval);
    result.document_interval = read_interval(
        settings, QStringLiteral("observation/document_interval_ms"), result.document_interval);
    return result;
}

void Configuration::validate() const
{
    validate_interval(general_interval);
    validate_interval(document_interval);
}

struct Completion::State
{
    explicit State(std::function<void()> callback)
    :
        release(std::move(callback))
    {}

    std::function<void()> release;
    std::atomic_bool completed{false};

    ~State() { finish(); }

    void finish()
    {
        if (!completed.exchange(true)) {
            release();
        }
    }
};

Completion::Completion(std::function<void()> release)
:
    m_state(std::make_shared<State>(std::move(release)))
{}

void Completion::complete()
{
    if (m_state) {
        m_state->finish();
        m_state.reset();
    }
}

bool Delivery::valid() const noexcept
{
    return active && active->load();
}

struct Wait_channel::Impl
{
    std::mutex mutex;
    std::condition_variable changed;
    std::optional<Delivery> pending;
    bool cancelled = false;
};

Wait_channel::Wait_channel()
:
    m_impl(std::make_unique<Impl>())
{}

Wait_channel::~Wait_channel()
{
    cancel();
}

std::optional<Delivery> Wait_channel::wait(Milliseconds timeout)
{
    std::unique_lock lock(m_impl->mutex);
    m_impl->changed.wait_for(lock, timeout, [this] {
        return m_impl->cancelled || m_impl->pending.has_value();
    });
    auto delivery = std::move(m_impl->pending);
    m_impl->pending.reset();
    if (delivery && !delivery->valid()) {
        return std::nullopt;
    }
    return delivery;
}

void Wait_channel::submit(Delivery delivery)
{
    std::lock_guard lock(m_impl->mutex);
    if (!m_impl->cancelled && delivery.valid()) {
        m_impl->pending.emplace(std::move(delivery));
        m_impl->changed.notify_one();
    }
}

void Wait_channel::cancel()
{
    std::optional<Delivery> pending;
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->cancelled = true;
        pending = std::move(m_impl->pending);
        m_impl->pending.reset();
        m_impl->changed.notify_all();
    }
}

namespace detail {

// Owns a subscription's user callbacks. A callback runs only while the gate is open.
// close() returns once every call running on another thread has left, and releases
// the callbacks on the closing thread. A callback that unsubscribes from inside
// itself is not waited for; the gate stays closed and releases its callables last.
class Subscriber_callbacks
{
public:
    Subscriber_callbacks(
        std::function<bool(const Event&)> classifier,
        Native_watcher::Directory_filter  directory_filter)
    :
        m_classifier(std::move(classifier)),
        m_directory_filter(std::move(directory_filter))
    {}

    // Both return std::nullopt once the subscription has been reset.
    std::optional<bool> classify(const Event& event)
    {
        return invoke([&] { return !m_classifier || m_classifier(event); });
    }

    std::optional<bool> admit_directory(const QString& root, const QString& child)
    {
        return invoke([&] { return m_directory_filter(root, child); });
    }

    void close()
    {
        // Declared before the lock, so released callables are destroyed after it.
        std::function<bool(const Event&)> classifier;
        Native_watcher::Directory_filter  directory_filter;
        std::unique_lock lock(m_mutex);
        m_open = false;
        const auto self = std::this_thread::get_id();
        m_left.wait(lock, [&] {
            return std::all_of(m_callers.begin(), m_callers.end(), [&](std::thread::id caller) {
                return caller == self;
            });
        });
        if (m_callers.empty()) {
            classifier       = std::move(m_classifier);
            directory_filter = std::move(m_directory_filter);
        }
    }

private:
    template <typename Call>
    std::optional<bool> invoke(const Call& call)
    {
        {
            std::lock_guard lock(m_mutex);
            if (!m_open) {
                return std::nullopt;
            }
            m_callers.push_back(std::this_thread::get_id());
        }
        const auto leave = qScopeGuard([this] {
            std::lock_guard lock(m_mutex);
            m_callers.erase(std::find(m_callers.begin(), m_callers.end(), std::this_thread::get_id()));
            m_left.notify_all();
        });
        return call();
    }

    std::function<bool(const Event&)> m_classifier;
    Native_watcher::Directory_filter  m_directory_filter;
    std::mutex                        m_mutex;
    std::condition_variable           m_left;
    std::vector<std::thread::id>      m_callers;
    bool                              m_open = true;
};

// Some supported standard libraries lack the C++20 atomic smart-pointer
// specializations. Keep publication private and identical on every platform.
template<typename Pointer>
class Published_pointer
{
public:
    Pointer load() const
    {
        std::lock_guard lock(m_mutex);
        return m_value;
    }

    void store(Pointer value)
    {
        {
            std::lock_guard lock(m_mutex);
            m_value.swap(value);
        }
        // Releasing the old native owner may join threads that query this
        // publication. Destroy it only after releasing the publication lock.
    }

private:
    mutable std::mutex m_mutex;
    Pointer m_value;
};

struct Native_group
{
    uint64_t id = 0;
    QList<Watch_spec> directories;
    QList<path_name::Key> directory_keys;
    QMap<path_name::Key, QList<qsizetype>> directory_indices;
    Watch_mode mode = Watch_mode::RECURSIVE;
    std::shared_ptr<path_name::Policy_epoch> policy;
    std::shared_ptr<path_name::Policy_epoch> source_policy;
    Native_watcher::Directory_filter directory_filter;
    std::atomic_uint64_t requested_eligibility = 0;
    std::atomic_uint64_t applied_eligibility = 0;
    Published_pointer<std::shared_ptr<Native_watcher>> watcher;
    bool started = false;
    bool wanted = true;
};

QString registered_path(const Native_group& group, const QString& path)
{
    const auto candidates = group.directory_indices.constFind(path_name::matching_bucket(path));
    if (candidates == group.directory_indices.cend()) {
        return {};
    }
    for (const auto index : *candidates) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::coverage_read_candidates;
#endif
        if (path_name::matches_key(path, group.directory_keys[index])) {
            return group.directories[index].path;
        }
    }
    return {};
}

struct Slot
{
    uint64_t id = 0;
    Subscription_options options;
    QList<path_name::Key> directory_keys;
    QList<path_name::Key> exact_keys;
    std::shared_ptr<Native_group> group;
    std::shared_ptr<Delivery_channel> channel;
    std::shared_ptr<Subscriber_callbacks> callbacks;
    std::shared_ptr<Subscriber_callbacks> filter_callbacks;
    std::vector<std::weak_ptr<Subscriber_callbacks>> retired_filters;
    std::shared_ptr<std::atomic_bool> active = std::make_shared<std::atomic_bool>(true);
    Batch ingress;
    Batch pending;
    Batch obligation;
    QMap<QString, uint64_t> native_revisions;
    uint64_t event_sequence = 0;
    uint64_t coverage_sequence = 0;
    uint64_t dirty_event = 0;
    uint64_t dirty_coverage = 0;
    uint64_t dispatched_event = 0;
    uint64_t dispatched_coverage = 0;
    uint64_t classifying_rescan_sequence = 0;
    bool outstanding = false;
    std::optional<Clock::time_point> deadline;
};

struct Service_state : std::enable_shared_from_this<Service_state>
{
    explicit Service_state(limits_t requested_limits)
    :
        limits(requested_limits)
    {}

    std::mutex mutex;
    std::condition_variable changed;
    // Native registration/destruction may join native threads, never under mutex.
    std::mutex registration_mutex;
    std::condition_variable registration_changed;
    bool registration_stopped = false;
    size_t retiring_groups = 0;
    QMap<uint64_t, std::shared_ptr<Slot>> subscriptions;
    std::vector<std::shared_ptr<Native_group>> groups;
    Published_pointer<std::weak_ptr<Direct_registry>> direct_registry;
    std::shared_ptr<path_name::Policy_epoch> default_policy =
        std::make_shared<path_name::Policy_epoch>();
    std::thread scheduler;
    std::thread registration_worker;
    limits_t limits;
    statistics_t counters;
    uint64_t next_id = 1;
    uint64_t sequence = 0;
    Milliseconds test_offset{0};
    std::optional<Clock::time_point> test_clock;
    bool stopped = false;

    Clock::time_point now() const { return test_clock.value_or(Clock::now()) + test_offset; }

    void promote(Batch& batch, const QString& diagnostic)
    {
        if (!batch.rescan_required) {
            ++counters.promotions;
        }
        batch.events.clear();
        batch.scopes.clear();
        batch.all_interests = true;
        batch.rescan_required = true;
        batch.consumer_reconciliation_only = false;
        batch.initial_admission_only = false;
        batch.diagnostic = diagnostic.left(1024);
    }

    void merge(Batch& target, const Batch& source)
    {
        const auto previous_sequence = target.capture.event_sequence;
        const bool previous_work = has_work(target);
        const bool previous_consumer_only = target.consumer_reconciliation_only;
        const bool previous_local = previous_consumer_only || target.initial_admission_only;
        const bool source_local = source.consumer_reconciliation_only || source.initial_admission_only;
        const bool source_dominates = previous_local && !source_local;
        const bool preserve_cause = previous_work && !previous_local &&
            source_local && !target.diagnostic.isEmpty();
        if (has_work(source)) {
            target.initial_admission_only = !previous_work
                ? source.initial_admission_only
                : previous_local && source_local &&
                    (target.initial_admission_only || source.initial_admission_only);
            target.consumer_reconciliation_only = !has_work(target)
                ? source.consumer_reconciliation_only
                : target.consumer_reconciliation_only && source.consumer_reconciliation_only;
        }
        target.capture.event_sequence = std::max(
            target.capture.event_sequence, source.capture.event_sequence);
        target.capture.coverage_sequence = std::max(
            target.capture.coverage_sequence, source.capture.coverage_sequence);
        target.rescan_required |= source.rescan_required;
        if (!source.diagnostic.isEmpty() && !preserve_cause &&
            (target.diagnostic.isEmpty() || source_dominates ||
                source.capture.event_sequence >= previous_sequence))
        {
            target.diagnostic = source.diagnostic.left(1024);
        }
        if (source.all_interests) {
            target.all_interests = true;
            target.scopes.clear();
        }
        if (!target.all_interests) {
            for (const auto& scope : source.scopes) {
                if (!target.scopes.contains(scope)) {
                    if (size_t(target.scopes.size()) >= limits.retained_scopes) {
                        promote(target, QStringLiteral("Observation scope detail limit exceeded"));
                        break;
                    }
                    target.scopes.append(scope);
                }
            }
        }
        if (target.all_interests && target.rescan_required) {
            target.events.clear();
            return;
        }
        size_t characters = 0;
        for (const auto& scope : target.scopes) {
            characters += size_t(scope.size());
        }
        if (characters > limits.retained_characters) {
            promote(target, QStringLiteral("Observation scope detail limit exceeded"));
            return;
        }
        for (const auto& event : target.events) {
            characters += size_t(event.path.size() + event.old_path.size());
        }
        for (const auto& event : source.events) {
            // Entry type takes part: a path that was a file and is now a directory
            // must keep its directory event for the classifier.
            if (target.events.contains(event)) {
                continue;
            }
            characters += size_t(event.path.size() + event.old_path.size());
            if (size_t(target.events.size()) >= limits.retained_events ||
                characters > limits.retained_characters)
            {
                promote(target, QStringLiteral("Observation path detail limit exceeded"));
                break;
            }
            target.events.append(event);
        }
    }

    void ingest(uint64_t group_id, uint64_t only_slot, const Native_batch& native)
    {
        std::lock_guard lock(mutex);
        if (stopped) {
            return;
        }
        const auto event_sequence = ++sequence;
        for (const auto& slot : subscriptions) {
            if ((only_slot && slot->id != only_slot) ||
                (!only_slot && slot->group->id != group_id))
            {
                continue;
            }
            Batch input;
            input.capture.event_sequence = event_sequence;
            const auto previous = slot->native_revisions.value(native.root);
            const bool coverage_changed = previous != native.coverage_revision;
            if (coverage_changed) {
                slot->native_revisions[native.root] = native.coverage_revision;
                slot->coverage_sequence = event_sequence;
            }
            input.capture.coverage_sequence = slot->coverage_sequence;
            input.rescan_required =
                (native.rescan_required && !native.rescan_event_paths_complete) ||
                native.events.isEmpty() || coverage_changed;
            input.diagnostic = native.diagnostic.left(1024);
            input.consumer_reconciliation_only = native.consumer_reconciliation_only && native.events.isEmpty();
            input.initial_admission_only = native.initial_admission_only && native.events.isEmpty();
            if (coverage_changed && input.diagnostic.isEmpty()) {
                input.diagnostic = QStringLiteral("Observation coverage changed; reconciliation required");
            }
            input.all_interests = native.scope.isEmpty() && native.root.isEmpty();
            if (native.scope.size() > qsizetype(limits.retained_characters)) {
                input.all_interests = true;
                input.rescan_required = true;
                input.consumer_reconciliation_only = false;
                input.initial_admission_only = false;
            }
            else {
                input.scopes.append(native.scope.isEmpty() ? native.root : native.scope);
            }
            // The native batch is borrowed. Enforce limits before making any owning copy.
            for (const auto& event : native.events) {
                Batch one;
                one.events.append(event);
                merge(input, one);
                if (input.all_interests && input.rescan_required) {
                    break;
                }
            }
            merge(slot->ingress, input);
        }
        changed.notify_one();
    }

    void reconcile_coverage(const Native_group& group, const Native_watcher& watcher, uint64_t only_slot)
    {
        for (const auto& directory : group.directories) {
            Native_batch armed;
            armed.root = directory.path;
            armed.scope = directory.path;
            armed.coverage_revision = watcher.coverage_revision(directory.path);
            armed.rescan_required = true;
            armed.initial_admission_only = watcher.covers_directory(directory.path);
            armed.diagnostic = armed.initial_admission_only
                ? QStringLiteral("Observation coverage armed; reconciliation required")
                : QStringLiteral("Observation coverage incomplete; reconciliation required");
            ingest(group.id, only_slot, armed);
        }
    }

    // Returns std::nullopt once the subscription has been reset.
    std::optional<bool> relevant(const Slot& slot, const Event& event) const
    {
        if (!(slot.options.event_kinds & uint32_t(event.kind))) {
            return false;
        }
        const auto matches_path = [&](const QString& path) {
            if (path.isEmpty()) {
                return false;
            }
            if (slot.options.directories.isEmpty() && slot.options.exact_files.isEmpty()) {
                return true;
            }
            for (const auto& file : slot.exact_keys) {
                if (path_name::matches_key(path, file) || path_name::is_ancestor_of_key(path, file)) {
                    return true;
                }
            }
            for (qsizetype index = 0; index < slot.directory_keys.size(); ++index) {
                const auto& directory = slot.options.directories[index];
                if (!path_name::is_within_key(path, slot.directory_keys[index])) {
                    continue;
                }
                if (directory.maximum_depth <= 0) {
                    return true;
                }
                const auto relative = QDir(directory.path).relativeFilePath(path);
                if (relative.count(QLatin1Char('/')) <= directory.maximum_depth) {
                    return true;
                }
            }
            return false;
        };
        if (!matches_path(event.path) && !matches_path(event.old_path)) {
            return false;
        }
        return slot.callbacks->classify(event);
    }

    void completed(uint64_t id)
    {
        std::lock_guard lock(mutex);
        const auto found = subscriptions.find(id);
        if (found != subscriptions.end()) {
            (*found)->outstanding = false;
            changed.notify_one();
        }
    }

    void run()
    {
        std::unique_lock lock(mutex);
        while (!stopped) {
            std::vector<std::pair<std::shared_ptr<Slot>, Batch>> inputs;
            for (const auto& slot : subscriptions) {
                if (has_work(slot->ingress)) {
                    slot->classifying_rescan_sequence = slot->ingress.rescan_required
                        ? slot->ingress.capture.event_sequence : 0;
                    inputs.emplace_back(slot, std::exchange(slot->ingress, Batch{}));
                }
            }
            lock.unlock();
            for (auto& [slot, input] : inputs) {
                if (!input.rescan_required) {
                    QList<Event> classified;
                    try {
                        for (const auto& event : input.events) {
                            const auto relevant_event = relevant(*slot, event);
                            if (!relevant_event) {
                                // Reset has deactivated the slot; its input is discarded.
                                break;
                            }
                            if (*relevant_event) {
                                classified.append(event);
                            }
                        }
                        input.events = std::move(classified);
                        input.rescan_required = std::any_of(input.events.cbegin(), input.events.cend(),
                            [](const Event& event) {
                                return event.kind == Event_kind::RENAMED &&
                                    (event.path.isEmpty() || event.old_path.isEmpty());
                            });
                    }
                    catch (...) {
                        input.events.clear();
                        input.rescan_required = true;
                        input.all_interests = true;
                        input.consumer_reconciliation_only = false;
                        input.initial_admission_only = false;
                        input.diagnostic = QStringLiteral("Observation classification failed");
                    }
                }
            }
            lock.lock();
            for (auto& [slot, input] : inputs) {
                slot->classifying_rescan_sequence = 0;
                if (!slot->active->load() || !has_work(input)) {
                    continue;
                }
                slot->event_sequence = input.capture.event_sequence;
                merge(slot->pending, input);
                if (!input.initial_admission_only && !input.consumer_reconciliation_only) {
                    // Detailed work does not extend acknowledgement's sequence,
                    // but an open local reconciliation loses both purity claims
                    // until its readback is acknowledged.
                    slot->obligation.initial_admission_only = false;
                    slot->obligation.consumer_reconciliation_only = false;
                }
                // Only work that itself needs reconciliation extends the obligation.
                // Detail arriving while it is open stays pending detail and is
                // delivered after acknowledgement, so it must not keep it open.
                if (slot->pending.rescan_required) {
                    slot->dirty_event = slot->event_sequence;
                    slot->dirty_coverage = slot->coverage_sequence;
                    Batch obligation = slot->pending;
                    obligation.events.clear();
                    merge(slot->obligation, obligation);
                }
            }
            std::vector<std::pair<std::shared_ptr<Delivery_channel>, Delivery>> deliveries;
            auto next_wake = Clock::time_point::max();
            const auto current = now();
            for (const auto& slot : subscriptions) {
                if (slot->deadline && *slot->deadline <= current && !has_work(slot->pending)) {
                    slot->deadline.reset();
                }
                if (has_work(slot->pending) && !slot->outstanding &&
                    (!slot->deadline || *slot->deadline <= current))
                {
                    auto batch = std::exchange(slot->pending, Batch{});
                    if (slot->dirty_event) {
                        merge(batch, slot->obligation);
                    }
                    batch.capture = {slot->id, slot->id, slot->event_sequence, slot->coverage_sequence};
                    batch.rescan_required |= slot->dirty_event != 0;
                    slot->dispatched_event = batch.capture.event_sequence;
                    slot->dispatched_coverage = batch.capture.coverage_sequence;
                    slot->outstanding = true;
                    slot->deadline = current + slot->options.interval;
                    ++counters.dispatches;
                    std::weak_ptr<Service_state> weak = shared_from_this();
                    Completion completion([weak, id = slot->id] {
                        if (const auto state = weak.lock()) {
                            state->completed(id);
                        }
                    });
                    deliveries.emplace_back(slot->channel,
                        Delivery{std::move(batch), std::move(completion), slot->active});
                }
                if (slot->deadline && *slot->deadline > current) {
                    next_wake = std::min(next_wake, *slot->deadline);
                }
            }
            lock.unlock();
            for (auto& [channel, delivery] : deliveries) {
                channel->submit(std::move(delivery));
            }
            // Retired subscription state must not survive an idle condition wait.
            // Release transfers outside the lock because completion takes it.
            inputs.clear();
            deliveries.clear();
            lock.lock();
            // Check ingress after submissions: completion or native arrival may have
            // happened with the lock released, before wait could observe its signal.
            bool ready = stopped;
            for (const auto& slot : subscriptions) {
                ready |= has_work(slot->ingress) ||
                    (has_work(slot->pending) && !slot->outstanding &&
                     (!slot->deadline || *slot->deadline <= now()));
            }
            if (ready) {
                continue;
            }
            if (next_wake == Clock::time_point::max()) {
                changed.wait(lock);
            }
            else {
                changed.wait_for(lock, std::max(Clock::duration::zero(), next_wake - now()));
            }
        }
    }

    void remove(uint64_t id)
    {
        std::unique_lock registration_lock(registration_mutex);
        std::shared_ptr<Slot> retired;
        {
            std::lock_guard lock(mutex);
            const auto found = subscriptions.find(id);
            if (found == subscriptions.end()) {
                return;
            }
            retired = *found;
            retired->active->store(false);
            subscriptions.erase(found);
            changed.notify_one();
        }
        retired->channel->cancel();
        const auto group = retired->group;
        bool referenced = false;
        {
            std::lock_guard lock(mutex);
            for (const auto& slot : subscriptions) {
                referenced |= slot->group == group;
            }
        }
        if (!referenced) {
            group->wanted = false;
            if (!group->started) {
                std::erase(groups, group);
            }
            registration_changed.notify_one();
        }
        registration_lock.unlock();
        // Native registration may still be retiring, and the scheduler may be inside
        // the classifier. Wait out such calls without service locks: a callback may
        // itself query the service.
        retired->callbacks->close();
        if (retired->filter_callbacks) {
            retired->filter_callbacks->close();
        }
        for (const auto& weak : retired->retired_filters) {
            if (const auto callbacks = weak.lock()) {
                callbacks->close();
            }
        }
    }

    bool replace_filter(uint64_t id, Native_watcher::Directory_filter filter)
    {
        if (!filter) {
            return false;
        }
        auto callbacks = std::make_shared<Subscriber_callbacks>(
            std::function<bool(const Event&)>{}, std::move(filter));
        std::shared_ptr<Subscriber_callbacks> previous;
        Native_watcher::Directory_filter previous_filter;
        std::lock_guard registration_lock(registration_mutex);
        {
            std::lock_guard lock(mutex);
            const auto slot = subscriptions.value(id);
            if (!slot || !slot->filter_callbacks || slot->options.mode == Watch_mode::DIRECT) {
                return false;
            }
            std::erase_if(slot->retired_filters, [](const auto& weak) { return weak.expired(); });
            previous = std::exchange(slot->filter_callbacks, callbacks);
            slot->retired_filters.push_back(previous);
            previous_filter = std::exchange(slot->group->directory_filter,
                [callbacks](const QString& root, const QString& child) {
                    return callbacks->admit_directory(root, child).value_or(false);
                });
            ++slot->group->requested_eligibility;
        }
        Native_batch changed_plan;
        changed_plan.rescan_required = true;
        changed_plan.consumer_reconciliation_only = true;
        changed_plan.diagnostic = QStringLiteral("Directory eligibility changed; reconciliation required");
        ingest(0, id, changed_plan);
        registration_changed.notify_one();
        return true;
    }

    void run_registrations()
    {
        std::unique_lock lock(registration_mutex);
        while (!registration_stopped) {
            std::shared_ptr<Native_group> work;
            bool retire = false;
            for (const auto& group : groups) {
                if (!group->wanted || !group->started ||
                    group->requested_eligibility.load() != group->applied_eligibility.load())
                {
                    work = group;
                    retire = !group->wanted;
                    group->started = true;
                    break;
                }
            }
            if (!work) {
                registration_changed.wait(lock);
                continue;
            }
            if (retire) {
                std::erase(groups, work);
                ++retiring_groups;
            }
            const auto eligibility_generation = work->requested_eligibility.load();
            auto directory_filter = work->directory_filter;
            lock.unlock();
            if (retire) {
                work->watcher.store({});
            }
            else {
                std::weak_ptr<Service_state> weak = shared_from_this();
                auto watcher = work->watcher.load();
                if (!watcher) {
                    watcher = std::make_shared<Native_watcher>(
                        [weak, id = work->id](const Native_batch& batch) {
                            if (const auto state = weak.lock()) {
                                state->ingest(id, 0, batch);
                            }
                        }, work->mode, QStringLiteral("filesystem observation"), work->policy,
                        Native_watcher::Failure_callback{}, directory_filter);
                    {
                        auto registry = direct_registry.load().lock();
                        if (!registry) {
                            registry = std::make_shared<Direct_registry>(direct_limits_t{
                                limits.native_registrations, limits.native_bytes,
                                limits.scan_workers, limits.plan_bytes,
                                limits.workload_admission == Workload_admission::BOUNDED});
                            direct_registry.store(registry);
                        }
                        watcher->set_direct_registry(std::move(registry));
                    }
                }
                {
                    // The shared registry publishes its own post-arm reconciliation.
                    // Its callback must already have a queryable coverage owner.
                    work->watcher.store(watcher);
                }
                watcher->replace_directory_filter(directory_filter, eligibility_generation);
                watcher->set_directories_with_depths(work->directories);
                work->applied_eligibility.store(eligibility_generation);
                // Native coverage getters synchronize with its registration/retry
                // state; readers may retain this owner across runtime rearming.
                work->watcher.store(watcher);
                // Enumeration started before arming cannot certify a clean snapshot.
                // Post-arm reconciliation closes that gap after initial or restored coverage.
            }
            directory_filter = {};
            lock.lock();
            if (retire) {
                --retiring_groups;
            }
        }
        auto retired = std::exchange(groups, {});
        retiring_groups += retired.size();
        lock.unlock();
        for (const auto& group : retired) {
            group->watcher.store({});
            std::lock_guard completed_lock(registration_mutex);
            --retiring_groups;
        }
    }
};

} // namespace detail

Subscription::Subscription(std::shared_ptr<detail::Service_state> state, uint64_t id)
:
    m_state(std::move(state)),
    m_id(id)
{}

Subscription::~Subscription() { reset(); }

Subscription::Subscription(Subscription&& other) noexcept
:
    m_state(std::move(other.m_state)),
    m_id(std::exchange(other.m_id, 0))
{}

Subscription& Subscription::operator=(Subscription&& other) noexcept
{
    if (this != &other) {
        reset();
        m_state = std::move(other.m_state);
        m_id = std::exchange(other.m_id, 0);
    }
    return *this;
}

void Subscription::reset()
{
    if (m_state) {
        m_state->remove(m_id);
        m_state.reset();
        m_id = 0;
    }
}

void Subscription::update_interval(Milliseconds interval)
{
    validate_interval(interval);
    if (!m_state) {
        throw std::logic_error("Observation subscription is inactive");
    }
    std::lock_guard lock(m_state->mutex);
    const auto slot = m_state->subscriptions.value(m_id);
    if (slot) {
        slot->options.interval = interval;
    }
}

Milliseconds Subscription::effective_interval() const
{
    if (!m_state) {
        return Milliseconds(0);
    }
    std::lock_guard lock(m_state->mutex);
    const auto slot = m_state->subscriptions.value(m_id);
    return slot ? slot->options.interval : Milliseconds(0);
}

bool Subscription::acknowledge(capture_t capture)
{
    if (!m_state || capture.subscription_id != m_id || capture.generation != m_id) {
        return false;
    }
    // Releasing the last watcher can join its callback thread. Keep that release
    // outside the service lock, just as registration retirement does.
    std::shared_ptr<Native_watcher> watcher;
    std::lock_guard lock(m_state->mutex);
    const auto slot = m_state->subscriptions.value(m_id);
    if (!slot || capture.event_sequence > slot->dispatched_event ||
        capture.coverage_sequence > slot->dispatched_coverage)
    {
        return false;
    }
    watcher = slot->group->watcher.load();
    if (watcher) {
        // Coverage loss is queryable before its callback arrives. A capture must
        // not acknowledge that newer revision during native retirement.
        for (const auto& directory : slot->group->directories) {
            if (watcher->coverage_revision(directory.path) > slot->native_revisions.value(directory.path)) {
                return false;
            }
        }
    }
    // Detail remains queued independently of the captured reconciliation. Only a
    // known newer rescan obligation can make this acknowledgement stale; a later
    // classification failure creates its own obligation when its input is merged.
    if (slot->dirty_event > capture.event_sequence ||
        slot->dirty_coverage > capture.coverage_sequence ||
        (slot->ingress.rescan_required &&
            slot->ingress.capture.event_sequence > capture.event_sequence) ||
        slot->classifying_rescan_sequence > capture.event_sequence ||
        slot->coverage_sequence > capture.coverage_sequence)
    {
        return false;
    }
    slot->dirty_event = 0;
    slot->dirty_coverage = 0;
    slot->obligation = {};
    return true;
}

bool Subscription::rescan_required() const
{
    if (!m_state) {
        return false;
    }
    std::lock_guard lock(m_state->mutex);
    const auto slot = m_state->subscriptions.value(m_id);
    return slot && (slot->dirty_event || slot->ingress.rescan_required);
}

bool Subscription::covers_directory(const QString& path) const
{
    if (!m_state) {
        return false;
    }
    std::shared_ptr<detail::Native_group> group;
    {
        std::lock_guard lock(m_state->mutex);
        const auto slot = m_state->subscriptions.value(m_id);
        if (slot) group = slot->group;
    }
    const auto watcher = group ? group->watcher.load() : nullptr;
    const auto registered = group ? detail::registered_path(*group, path) : QString();
    return watcher && !registered.isEmpty() &&
        group->requested_eligibility.load() == group->applied_eligibility.load() &&
        watcher->covers_directory(registered);
}

Coverage_status Subscription::coverage_status(const QString& path) const
{
    std::shared_ptr<detail::Native_group> group;
    if (m_state) {
        std::lock_guard lock(m_state->mutex);
        if (const auto slot = m_state->subscriptions.value(m_id)) {
            group = slot->group;
        }
    }
    const auto registered = group ? detail::registered_path(*group, path) : QString();
    if (registered.isEmpty()) {
        return {Coverage_state::FAILED, QStringLiteral("Directory is not an observed interest")};
    }
    const auto watcher = group->watcher.load();
    const auto status = watcher ? watcher->coverage_status(registered) : Coverage_status{};
    if (status.state != Coverage_state::FAILED &&
        group->requested_eligibility.load() != group->applied_eligibility.load())
    {
        return {};
    }
    return status;
}

uint64_t Subscription::coverage_revision(const QString& path) const
{
    if (!m_state) {
        return 0;
    }
    std::shared_ptr<detail::Native_group> group;
    {
        std::lock_guard lock(m_state->mutex);
        const auto slot = m_state->subscriptions.value(m_id);
        if (slot) group = slot->group;
    }
    const auto watcher = group ? group->watcher.load() : nullptr;
    const auto registered = group ? detail::registered_path(*group, path) : QString();
    return watcher && !registered.isEmpty() ? watcher->coverage_revision(registered) : 0;
}

void Subscription::request_rescan(const QString& reason)
{
    if (m_state) {
        Native_batch batch;
        batch.rescan_required = true;
        batch.diagnostic = reason;
        m_state->ingest(0, m_id, batch);
    }
}

bool Subscription::replace_directory_filter(Native_watcher::Directory_filter filter)
{
    return m_state && m_state->replace_filter(m_id, std::move(filter));
}

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
void Subscription::set_coverage_for_tests(const QString& path, bool covered)
{
    if (!m_state) {
        return;
    }
    std::shared_ptr<detail::Native_group> group;
    {
        std::lock_guard lock(m_state->mutex);
        const auto slot = m_state->subscriptions.value(m_id);
        if (slot) {
            group = slot->group;
        }
    }
    const auto watcher = group ? group->watcher.load() : nullptr;
    const auto registered = group ? detail::registered_path(*group, path) : QString();
    if (watcher && !registered.isEmpty()) {
        watcher->set_coverage_for_tests(registered, covered);
    }
}
#endif

Service::Service(limits_t limits)
:
    m_state(std::make_shared<detail::Service_state>(limits))
{
    if (!limits.retained_events || !limits.retained_characters || !limits.retained_scopes ||
        (limits.workload_admission == Workload_admission::BOUNDED &&
            (!limits.subscriptions || !limits.interest_characters)))
    {
        throw std::invalid_argument("Observation memory limits must be positive");
    }
    m_state->counters.control_threads = 2;
    try {
        m_state->scheduler = std::thread([state = m_state] {
            state->run();
            std::lock_guard lock(state->mutex);
            --state->counters.control_threads;
        });
        m_state->registration_worker = std::thread([state = m_state] {
            state->run_registrations();
            std::lock_guard lock(state->mutex);
            --state->counters.control_threads;
        });
    }
    catch (...) {
        shutdown();
        throw;
    }
}

Service::~Service() { shutdown(); }

Subscription Service::subscribe(Subscription_options options, std::shared_ptr<Delivery_channel> channel)
{
    validate_interval(options.interval);
    if (!channel) {
        throw std::invalid_argument("Observation delivery channel is required");
    }
    const bool bounded_workload = m_state->limits.workload_admission == Workload_admission::BOUNDED;
    if (bounded_workload && (options.directories.size() > 4096 || options.exact_files.size() > 4096)) {
        throw std::invalid_argument("Observation subscription interest limit exceeded");
    }
    if (!options.policy_epoch) {
        options.policy_epoch = m_state->default_policy;
    }
    for (auto& spec : options.directories) {
        spec.path = path_name::normalized(QFileInfo(spec.path).absoluteFilePath());
        if (spec.path.size() > 32768) {
            throw std::invalid_argument("Observation directory path exceeds the supported length");
        }
    }
    auto registration_directories = options.directories;
    if (options.directories.isEmpty() && !options.exact_files.isEmpty()) {
        options.mode = Watch_mode::DIRECT;
    }
    for (auto& file : options.exact_files) {
        file = path_name::normalized(QFileInfo(file).absoluteFilePath());
        if (file.size() > 32768) {
            throw std::invalid_argument("Observation file path exceeds the supported length");
        }
        const auto parent = QFileInfo(file).absolutePath();
        if (std::none_of(registration_directories.begin(), registration_directories.end(), [&](const Watch_spec& spec) {
            return spec.path == parent;
        })) {
            registration_directories.append({parent, 0});
        }
    }
    size_t interest_characters = 0;
    QStringList policy_paths;
    const auto count_interest = [&](const QString& path) {
        const auto count = size_t(path.size());
        if (count > std::numeric_limits<size_t>::max() - interest_characters) {
            throw std::overflow_error("Observation interest text accounting overflow");
        }
        interest_characters += count;
    };
    for (const auto& directory : registration_directories) {
        count_interest(directory.path);
        policy_paths.append(directory.path);
    }
    for (const auto& file : options.exact_files) {
        count_interest(file);
        policy_paths.append(file);
    }
    if (bounded_workload && interest_characters > m_state->limits.interest_characters) {
        throw std::invalid_argument("Observation subscription interest text budget exhausted");
    }
    std::lock_guard registration_lock(m_state->registration_mutex);
    std::shared_ptr<detail::Native_group> group;
    const auto source_policy = options.policy_epoch;
    std::shared_ptr<path_name::Policy_epoch> scoped_policy;
    Registration_projection registration;
    for (const auto& candidate : m_state->groups) {
        if (!candidate->wanted || options.directory_filter || candidate->directory_filter ||
            candidate->mode != options.mode || candidate->source_policy != source_policy)
        {
            continue;
        }
        // Existing captured root keys can reject unrelated groups without any OS
        // policy queries. Fork only when physical registration sharing is possible.
        QList<bool> matched(candidate->directories.size(), false);
        bool compatible_paths = true;
        for (const auto& directory : registration_directories) {
            bool found = false;
            for (qsizetype index = 0; index < candidate->directories.size(); ++index) {
                if (directory.maximum_depth == candidate->directories[index].maximum_depth &&
                    path_name::matches_key(directory.path, candidate->directory_keys[index]))
                {
                    matched[index] = true;
                    found = true;
                    break;
                }
            }
            if (!found) {
                compatible_paths = false;
                break;
            }
        }
        if (!compatible_paths || std::find(matched.begin(), matched.end(), false) != matched.end()) {
            continue;
        }
        auto fork = source_policy->fork_for_paths(
            policy_paths, m_state->limits.interest_characters, candidate->policy.get(), bounded_workload);
        if (!fork) {
            continue;
        }
        auto projected = project_registrations(registration_directories, *fork);
        if (projected.directories.size() != candidate->directories.size()) {
            continue;
        }
        bool same = true;
        for (qsizetype i = 0; i < projected.directories.size(); ++i) {
            same &= projected.directories[i].maximum_depth == candidate->directories[i].maximum_depth &&
                projected.keys[i] == candidate->directory_keys[i];
        }
        if (same) {
            group = candidate;
            scoped_policy = std::move(fork);
            registration = std::move(projected);
            break;
        }
    }
    const bool create_group = !group;
    const bool filtered     = bool(options.directory_filter);
    if (bounded_workload && create_group && m_state->groups.size() / 2 >= m_state->limits.subscriptions) {
        throw std::runtime_error("Observation native registration and retirement budget exhausted");
    }
    if (!scoped_policy) {
        scoped_policy = source_policy->fork_for_paths(
            policy_paths, m_state->limits.interest_characters, nullptr, bounded_workload);
        registration = project_registrations(registration_directories, *scoped_policy);
    }
    auto slot = std::make_shared<detail::Slot>();
    slot->callbacks = std::make_shared<detail::Subscriber_callbacks>(
        std::exchange(options.classifier, {}), Native_watcher::Directory_filter{});
    if (filtered) {
        slot->filter_callbacks = std::make_shared<detail::Subscriber_callbacks>(
            std::function<bool(const Event&)>{}, std::exchange(options.directory_filter, {}));
    }
    options.policy_epoch = scoped_policy;
    for (const auto& directory : options.directories) {
        slot->directory_keys.append(scoped_policy->key(directory.path));
    }
    for (const auto& file : options.exact_files) {
        slot->exact_keys.append(scoped_policy->key(file));
    }
    {
        std::lock_guard lock(m_state->mutex);
        if (m_state->stopped) {
            throw std::logic_error("Observation service has stopped");
        }
        if (bounded_workload && size_t(m_state->subscriptions.size()) >= m_state->limits.subscriptions) {
            throw std::runtime_error("Observation subscription budget exhausted");
        }
        if (m_state->next_id == std::numeric_limits<uint64_t>::max()) {
            throw std::overflow_error("Observation subscription identity space exhausted");
        }
        slot->id = m_state->next_id++;
        slot->options = std::move(options);
        slot->channel = std::move(channel);
        if (!group) {
            group = std::make_shared<detail::Native_group>();
            group->id = slot->id;
            group->directories = std::move(registration.directories);
            group->directory_keys = std::move(registration.keys);
            for (qsizetype index = 0; index < group->directories.size(); ++index) {
                group->directory_indices[path_name::matching_bucket(group->directory_keys[index])].append(index);
            }
            group->mode = slot->options.mode;
            group->policy = slot->options.policy_epoch;
            group->source_policy = source_policy;
            if (filtered) {
                group->directory_filter =
                    [callbacks = slot->filter_callbacks](const QString& root, const QString& child) {
                        return callbacks->admit_directory(root, child).value_or(false);
                    };
            }
        }
        slot->group = group;
        m_state->subscriptions.insert(slot->id, slot);
    }
    if (create_group) {
        m_state->groups.push_back(group);
        m_state->registration_changed.notify_one();
    }
    else
    if (const auto watcher = group->watcher.load()) {
        // Existing coverage does not establish the new subscriber's snapshot.
        // An unpublished watcher instead reconciles every slot after arming.
        m_state->reconcile_coverage(*group, *watcher, slot->id);
    }
    return Subscription(m_state, slot->id);
}

statistics_t Service::statistics() const
{
    std::lock_guard registration_lock(m_state->registration_mutex);
    std::lock_guard lock(m_state->mutex);
    auto result = m_state->counters;
    std::set<const path_name::Policy_epoch*> counted_policies;
    const auto count_policy = [&](const std::shared_ptr<path_name::Policy_epoch>& policy) {
        if (counted_policies.insert(policy.get()).second) {
            const auto usage = policy->cache_usage();
            result.policy_cache_entries += usage.entries;
            result.policy_cache_characters += usage.characters;
        }
    };
    count_policy(m_state->default_policy);
    result.retiring_groups = m_state->retiring_groups;
    for (const auto& group : m_state->groups) {
        count_policy(group->policy);
        if (!group->wanted) {
            ++result.retiring_groups;
        }
        else
        if (!group->watcher.load()) {
            ++result.pending_registrations;
        }
    }
    result.subscriptions = size_t(m_state->subscriptions.size());
    for (const auto& slot : m_state->subscriptions) {
        count_policy(slot->options.policy_epoch);
        result.retained_events += size_t(slot->pending.events.size() + slot->ingress.events.size());
        result.outstanding += slot->outstanding ? 1 : 0;
    }
    return result;
}

void Service::shutdown()
{
    std::unique_lock registration_lock(m_state->registration_mutex);
    QList<std::shared_ptr<detail::Slot>> retired;
    {
        std::lock_guard lock(m_state->mutex);
        if (m_state->stopped) {
            return;
        }
        m_state->stopped = true;
        retired = m_state->subscriptions.values();
        for (const auto& slot : retired) {
            slot->active->store(false);
        }
        m_state->subscriptions.clear();
        m_state->changed.notify_all();
    }
    for (const auto& slot : retired) {
        slot->channel->cancel();
    }
    m_state->registration_stopped = true;
    m_state->registration_changed.notify_one();
    registration_lock.unlock();
    if (m_state->scheduler.joinable()) {
        m_state->scheduler.join();
    }
    if (m_state->registration_worker.joinable()) {
        m_state->registration_worker.join();
    }
    {
        std::lock_guard lock(m_state->mutex);
        m_state->counters.control_threads = 0;
    }
    retired.clear();
}

Resource_counts Service::resource_counts() const
{
    std::lock_guard lock(m_state->registration_mutex);
    Resource_counts result;
    if (const auto registry = m_state->direct_registry.load().lock()) {
        result = registry->resource_counts();
    }
    for (const auto& group : m_state->groups) {
        if (!group->watcher.load()) {
            result.desired += int(group->directories.size());
        }
    }
    return result;
}

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
bool Service::set_directory_available_for_tests(const QString& path, bool available)
{
    std::lock_guard lock(m_state->registration_mutex);
    if (const auto registry = m_state->direct_registry.load().lock()) {
        return registry->set_directory_available_for_tests(path, available);
    }
    return false;
}

QStringList Service::armed_directories_for_tests() const
{
    std::lock_guard lock(m_state->registration_mutex);
    if (const auto registry = m_state->direct_registry.load().lock()) {
        return registry->armed_directories_for_tests();
    }
    return {};
}

QStringList Service::covered_logical_directories_for_tests() const
{
    std::lock_guard lock(m_state->registration_mutex);
    if (const auto registry = m_state->direct_registry.load().lock()) {
        return registry->covered_logical_directories_for_tests();
    }
    return {};
}

void Service::ingest_for_tests(const Subscription& subscription, const Native_batch& batch)
{
    m_state->ingest(0, subscription.m_id, batch);
}

void Service::advance_clock_for_tests(Milliseconds elapsed)
{
    if (elapsed.count() < 0) {
        throw std::invalid_argument("Observation clock cannot move backwards");
    }
    std::lock_guard lock(m_state->mutex);
    m_state->test_offset += elapsed;
    m_state->changed.notify_one();
}

void Service::use_manual_clock_for_tests()
{
    std::lock_guard lock(m_state->mutex);
    if (!m_state->subscriptions.isEmpty()) {
        throw std::logic_error("Set the observation clock before subscribing");
    }
    m_state->test_clock = Clock::time_point{};
}
#endif

} // namespace vnm::filesystem_observation
