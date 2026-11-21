#include "vnm_filesystem_native_watcher.h"
#include "vnm_direct_registry_p.h"
#include "vnm_native_event_decode_p.h"
#include "vnm_native_test_hooks_p.h"
#include "vnm_filesystem_observation_variant.h"

#include <QFileInfo>

#include <mutex>
#include <utility>

VNM_FILESYSTEM_OBSERVATION_REFERENCE_VARIANT(native_watcher)

namespace vnm::filesystem_observation {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
namespace native_hooks = detail::native_test_hooks;
#endif

struct Native_watcher::Impl
{
    Impl(Callback callback, Watch_mode mode, QString label,
        std::shared_ptr<path_name::Policy_epoch> policy, Failure_callback failure,
        Directory_filter filter)
    :
        callback([callback = std::move(callback), failure = std::move(failure)](const Native_batch& batch) {
            callback(batch);
            if (failure && batch.reason == Native_reason::REGISTRATION_FAILED) {
                failure(batch.root);
            }
        }),
        directory_filter(std::move(filter)),
        mode(mode),
        label(std::move(label)),
        policy_epoch(policy ? std::move(policy) : std::make_shared<path_name::Policy_epoch>())
    {}

    Callback callback;
    Directory_filter directory_filter;
    Watch_mode mode;
    QString label;
    std::shared_ptr<path_name::Policy_epoch> policy_epoch;
    std::shared_ptr<detail::Direct_registry> direct_registry;
    uint64_t direct_client = 0;
    uint64_t eligibility_generation = 0;
    QList<Watch_spec> direct_paths;
    bool shared_registry = false;
    std::mutex mutex;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    std::function<void(Expansion_stage)> expansion_observer;
#endif
};

Native_watcher::Native_watcher(
    Callback callback,
    Watch_mode mode,
    QString label,
    std::shared_ptr<path_name::Policy_epoch> policy_epoch,
    Failure_callback failure_callback,
    Directory_filter directory_filter)
:
    d(std::make_unique<Impl>(
        std::move(callback),
        mode,
        std::move(label),
        std::move(policy_epoch),
        std::move(failure_callback),
        std::move(directory_filter)))
{}

Native_watcher::~Native_watcher()
{
    clear();
}

void Native_watcher::set_direct_registry(std::shared_ptr<detail::Direct_registry> registry)
{
    const std::lock_guard lock(d->mutex);
    Q_ASSERT(d->direct_client == 0);
    d->shared_registry = true;
    d->direct_registry = std::move(registry);
}

void Native_watcher::set_policy_epoch(
    std::shared_ptr<path_name::Policy_epoch> policy_epoch)
{
    std::unique_lock lock(d->mutex);
    if (!policy_epoch || policy_epoch == d->policy_epoch) {
        return;
    }
    d->policy_epoch = policy_epoch;
    const auto registry = d->direct_registry;
    const auto client = d->direct_client;
    const auto paths = d->direct_paths;
    const auto filter = d->directory_filter;
    const auto generation = d->eligibility_generation;
    lock.unlock();
    if (client != 0) {
        registry->replace(client, paths, d->mode, std::move(policy_epoch), filter, false, generation);
    }
}

void Native_watcher::replace_directory_filter(Directory_filter filter, uint64_t generation)
{
    Directory_filter retired;
    std::unique_lock lock(d->mutex);
    retired = std::exchange(d->directory_filter, filter);
    d->eligibility_generation = generation;
    const auto registry = d->direct_registry;
    const auto client = d->direct_client;
    const auto paths = d->direct_paths;
    const auto policy = d->policy_epoch;
    lock.unlock();
    if (client != 0) {
        registry->replace(client, paths, d->mode, policy, std::move(filter), false, generation);
    }
}

void Native_watcher::set_directories(
    const QStringList& directory_paths)
{
    QList<Watch_spec> directory_specs;
    directory_specs.reserve(directory_paths.size());
    const int maximum_depth =
        d->mode == Watch_mode::DISCOVERY_RECURSIVE
        ? 3
        : 0;
    for (const QString& path : directory_paths) {
        directory_specs.append({path, maximum_depth});
    }
    set_directories_with_depths(directory_specs);
}

void Native_watcher::set_directories_with_depths(
    const QList<Watch_spec>& directory_specs)
{
    QList<Watch_spec> paths;
    paths.reserve(directory_specs.size());
    for (const auto& specification : directory_specs) {
        paths.append({path_name::normalized(QFileInfo(specification.path).absoluteFilePath()),
            specification.maximum_depth});
    }
    if (paths.isEmpty()) {
        clear();
        return;
    }
    std::unique_lock lock(d->mutex);
    if (!d->direct_registry) {
        d->direct_registry = std::make_shared<detail::Direct_registry>();
    }
    if (d->direct_client == 0) {
        d->direct_client = d->direct_registry->attach(d->callback);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        d->direct_registry->set_expansion_observer_for_tests(d->direct_client, d->expansion_observer);
#endif
    }
    d->direct_paths = paths;
    const auto registry = d->direct_registry;
    const auto client = d->direct_client;
    const auto policy = d->policy_epoch;
    const auto filter = d->directory_filter;
    const auto generation = d->eligibility_generation;
    lock.unlock();
    registry->replace(client, paths, d->mode, policy, filter, !d->shared_registry, generation);
}

bool Native_watcher::covers_directory(const QString& path) const
{
    const std::lock_guard lock(d->mutex);
    return d->direct_client != 0 && d->direct_registry->covers(d->direct_client, path);
}

Coverage_status Native_watcher::coverage_status(const QString& path) const
{
    const std::lock_guard lock(d->mutex);
    if (d->direct_client == 0 && d->shared_registry && d->direct_registry) {
        return {};
    }
    return d->direct_client != 0
        ? d->direct_registry->coverage_status(d->direct_client, path)
        : Coverage_status{Coverage_state::FAILED, QStringLiteral("Directory watcher is inactive")};
}

uint64_t Native_watcher::coverage_revision(const QString& path) const
{
    const std::lock_guard lock(d->mutex);
    return d->direct_client != 0 ? d->direct_registry->revision(d->direct_client, path) : 0;
}

Resource_counts Native_watcher::resource_counts() const
{
    const std::lock_guard lock(d->mutex);
    return d->direct_registry ? d->direct_registry->resource_counts() : Resource_counts{};
}

void Native_watcher::clear()
{
    std::unique_lock lock(d->mutex);
    auto registry = std::move(d->direct_registry);
    const auto client = std::exchange(d->direct_client, 0);
    d->direct_paths.clear();
    lock.unlock();
    if (client != 0) {
        registry->detach(client);
    }
}

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
void Native_watcher::set_expansion_observer_for_tests(std::function<void(Expansion_stage)> observer)
{
    const std::lock_guard lock(d->mutex);
    d->expansion_observer = std::move(observer);
    if (d->direct_client != 0) {
        d->direct_registry->set_expansion_observer_for_tests(d->direct_client, d->expansion_observer);
    }
}

int Native_watcher::active_thread_count_for_tests()
{
    return native_hooks::direct_registry_threads.load() + native_hooks::native_drain_threads.load();
}

int Native_watcher::native_notification_count_for_tests()
{
    return native_hooks::native_notifications.load();
}

int Native_watcher::registration_attempt_count_for_tests()
{
    return native_hooks::registration_attempts.load();
}

void Native_watcher::set_coverage_for_tests(const QString& path, bool covered)
{
    const std::lock_guard lock(d->mutex);
    if (d->direct_client != 0) {
        d->direct_registry->set_coverage_for_tests(d->direct_client, path, covered);
    }
}

int Native_watcher::expansion_count_for_tests() const
{
    const std::lock_guard lock(d->mutex);
    return d->direct_client != 0 ? d->direct_registry->expansion_count_for_tests(d->direct_client) : 0;
}
#endif

#if defined(Q_OS_WIN) && \
    defined(VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS)
Native_batch Native_watcher::decode_windows_notifications_for_tests(
    const QString& root, const QByteArray& bytes)
{
    return detail::decode_windows_notifications(
        root, bytes.constData(), static_cast<uint32_t>(bytes.size())).batch;
}

void Native_watcher::set_windows_file_id_error_for_tests(uint32_t error)
{
    native_hooks::windows_file_id_error.store(error);
}

void Native_watcher::set_windows_completion_port_error_for_tests(uint32_t error)
{
    native_hooks::windows_completion_port_error.store(error);
}

void Native_watcher::set_windows_open_error_for_tests(uint32_t error)
{
    native_hooks::windows_open_error.store(error);
}

void Native_watcher::
set_windows_pause_before_first_arm_for_tests(bool pause)
{
    native_hooks::windows_first_arm_pause_released.store(!pause);
    native_hooks::windows_first_arm_pause_released.notify_all();
    native_hooks::windows_first_arm_pause_reached.store(false);
    native_hooks::windows_pause_before_first_arm_requested.store(pause);
}

bool Native_watcher::windows_first_arm_pause_reached_for_tests()
{
    return native_hooks::windows_first_arm_pause_reached.load();
}

void Native_watcher::set_windows_completion_error_for_tests(
    uint32_t error)
{
    native_hooks::windows_completion_error.store(error);
}

void Native_watcher::set_windows_zero_detail_completion_for_tests(bool enabled)
{
    native_hooks::windows_zero_detail_completion.store(enabled);
}

void Native_watcher::set_windows_hold_retired_completions_for_tests(bool hold)
{
    native_hooks::windows_hold_retired_completions.store(hold);
}

int Native_watcher::windows_held_retirement_count_for_tests()
{
    return native_hooks::windows_held_retirement_count.load();
}
#endif

#if defined(Q_OS_LINUX) && \
    defined(VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS)
void Native_watcher::set_linux_wake_error_for_tests(bool failed)
{
    native_hooks::linux_wake_error.store(failed);
}

void Native_watcher::
set_linux_add_watch_successes_before_failure_for_tests(int successful_adds)
{
    native_hooks::linux_add_watch_successes_before_failure.store(successful_adds);
}

void Native_watcher::
set_linux_add_watch_pause_before_attempt_for_tests(int successful_adds)
{
    native_hooks::linux_add_watch_pause_released.store(successful_adds < 0);
    native_hooks::linux_add_watch_pause_released.notify_all();
    native_hooks::linux_add_watch_pause_reached.store(false);
    native_hooks::linux_add_watch_successes_before_pause.store(successful_adds);
    if (successful_adds >= 0) {
        native_hooks::linux_add_watch_pause_released.store(false);
    }
}

bool Native_watcher::linux_add_watch_pause_reached_for_tests()
{
    return native_hooks::linux_add_watch_pause_reached.load();
}

void Native_watcher::release_linux_add_watch_pause_for_tests()
{
    native_hooks::linux_add_watch_pause_released.store(true);
    native_hooks::linux_add_watch_pause_released.notify_all();
}

int Native_watcher::linux_kernel_watch_count_for_tests() const
{
    return resource_counts().armed;
}

void Native_watcher::invalidate_linux_content_watches_for_tests()
{
    const std::lock_guard lock(d->mutex);
    if (d->direct_client != 0) {
        d->direct_registry->invalidate_content_for_tests(d->direct_client);
    }
}

void Native_watcher::inject_linux_overflow_for_tests()
{
    const std::lock_guard lock(d->mutex);
    if (d->direct_client != 0) {
        d->direct_registry->inject_overflow_for_tests(d->direct_client);
    }
}
#endif

} // namespace vnm::filesystem_observation
