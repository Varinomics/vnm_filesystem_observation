#pragma once

#include "vnm_path_name.h"
#include "vnm_filesystem_native_event.h"

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QList>

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>

namespace vnm::filesystem_observation {

// An owner can defer expansion until its directory policy has been validated.
// This keeps coverage incomplete without reporting a failed filesystem scan.
class Directory_filter_pending : public std::exception
{
public:
    const char* what() const noexcept override { return "Directory eligibility is pending"; }
};

namespace detail {
class Direct_registry;
struct Service_state;
}

// All modes share physical coverage. Windows uses recursive ancestor anchors;
// Linux arms each eligible directory nonrecursively before expanding it.
// Logical recursive expansion and discovery depth remain independent interests.
// Topology changes and lost detail retain reconciliation until coverage and the
// consumer's acquisition are complete.
enum class Watch_mode
{
    DIRECT,
    RECURSIVE,
    DISCOVERY_RECURSIVE,
};

struct Watch_spec
{
    QString path;
    int maximum_depth = 0;
};

class Native_watcher
{
public:
    using Callback = std::function<void(const Native_batch&)>;
    using Directory_filter = std::function<bool(const QString&, const QString&)>;
    using Failure_callback = std::function<void(const QString&)>;

    Native_watcher(
        Callback callback,
        Watch_mode mode,
        QString label = {},
        std::shared_ptr<vnm::path_name::Policy_epoch> policy_epoch = {},
        Failure_callback failure_callback = {},
        Directory_filter directory_filter = {});
    ~Native_watcher();

    void set_policy_epoch(
        std::shared_ptr<vnm::path_name::Policy_epoch> policy_epoch);
    void set_directories(const QStringList& directory_paths);
    void set_directories_with_depths(
        const QList<Watch_spec>& directory_specs);
    void clear();
    [[nodiscard]] Resource_counts resource_counts() const;
    [[nodiscard]] bool covers_directory(const QString& directory_path) const;
    [[nodiscard]] Coverage_status coverage_status(const QString& directory_path) const;
    // Changes on coverage loss and recovery, even when both occur between reads.
    [[nodiscard]] uint64_t coverage_revision(const QString& directory_path) const;

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    enum class Expansion_stage { BEFORE_RESULT, WAITING_FOR_RETIREMENT };
    void set_expansion_observer_for_tests(std::function<void(Expansion_stage)> observer);
    int expansion_count_for_tests() const;
    static int active_thread_count_for_tests();
    static int native_notification_count_for_tests();
    static int registration_attempt_count_for_tests();
    void set_coverage_for_tests(const QString& directory_path, bool covered);
#endif

#if defined(Q_OS_WIN) && \
    defined(VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS)
    static Native_batch decode_windows_notifications_for_tests(
        const QString& root, const QByteArray& bytes);
    static void set_windows_pause_before_first_arm_for_tests(bool pause);
    static bool windows_first_arm_pause_reached_for_tests();
    static void set_windows_completion_error_for_tests(uint32_t error);
    static void set_windows_open_error_for_tests(uint32_t error);
    static void set_windows_completion_port_error_for_tests(uint32_t error);
    static void set_windows_file_id_error_for_tests(uint32_t error);
    static void set_windows_zero_detail_completion_for_tests(bool enabled);
    static void set_windows_hold_retired_completions_for_tests(bool hold);
    static int windows_held_retirement_count_for_tests();
#endif

#if defined(Q_OS_LINUX) && \
    defined(VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS)
    static void set_linux_wake_error_for_tests(bool failed);
    static void set_linux_add_watch_successes_before_failure_for_tests(
        int successful_adds);
    static void set_linux_add_watch_pause_before_attempt_for_tests(
        int successful_adds);
    static bool linux_add_watch_pause_reached_for_tests();
    static void release_linux_add_watch_pause_for_tests();
    void invalidate_linux_content_watches_for_tests();
    void inject_linux_overflow_for_tests();
    int linux_kernel_watch_count_for_tests() const;
#endif

private:
    friend struct detail::Service_state;
    void set_direct_registry(std::shared_ptr<detail::Direct_registry> registry);
    void replace_directory_filter(Directory_filter filter, uint64_t generation);

    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace vnm::filesystem_observation
