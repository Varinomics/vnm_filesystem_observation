#pragma once

#include <QtGlobal>

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
#include <atomic>
#include <cstdint>

namespace vnm::filesystem_observation::detail::native_test_hooks {

inline std::atomic_int registration_attempts = 0;
inline std::atomic_int native_notifications = 0;
inline std::atomic_int direct_registry_threads = 0;
inline std::atomic_int native_drain_threads = 0;
inline std::atomic_uint64_t native_wait_returns = 0;
inline std::atomic_uint64_t native_handoff_waits = 0;
inline std::atomic_uint64_t native_capacity_changes = 0;
inline std::atomic_uint64_t registry_maintenance_turns = 0;
inline std::atomic_uint64_t reconciliation_turns = 0;
// Reader-local work excludes concurrent maintenance and acquisition queries.
inline thread_local uint64_t coverage_read_candidates = 0;
inline std::atomic_bool plan_allocation_failure = false;
inline std::atomic_bool scan_result_allocation_failure = false;
#ifdef Q_OS_WIN
inline std::atomic_uint64_t windows_parent_metadata_probes = 0;
inline std::atomic_uint64_t windows_identity_validations = 0;
inline std::atomic_uint64_t windows_descendant_identity_validations = 0;
inline std::atomic_uint64_t windows_ancestor_searches = 0;
inline std::atomic_uint64_t windows_logical_routes = 0;
inline std::atomic_uint64_t windows_route_entry_visits = 0;
inline std::atomic_bool windows_pause_uncovered_identity_requested = false;
inline std::atomic_bool windows_uncovered_identity_pause_reached = false;
inline std::atomic_bool windows_uncovered_identity_pause_released = true;
inline std::atomic_uint32_t windows_extended_read_error = 0;
inline std::atomic_bool windows_pause_before_first_arm_requested = false;
inline std::atomic_bool windows_first_arm_pause_reached = false;
inline std::atomic_bool windows_first_arm_pause_released = true;
inline std::atomic_uint32_t windows_completion_error = 0;
inline std::atomic_uint32_t windows_open_error = 0;
inline std::atomic_uint32_t windows_arm_error = 0;
inline std::atomic_int windows_failed_identity_opens = 0;
inline std::atomic_uint32_t windows_completion_port_error = 0;
inline std::atomic_uint32_t windows_wake_error = 0;
inline std::atomic_uint32_t windows_file_id_error = 0;
inline std::atomic_bool windows_zero_detail_completion = false;
inline std::atomic_bool windows_pause_basic_recovery_requested = false;
inline std::atomic_bool windows_basic_recovery_pause_reached = false;
inline std::atomic_bool windows_basic_recovery_pause_released = true;
inline std::atomic_bool windows_hold_retired_completions = false;
inline std::atomic_int windows_held_retirement_count = 0;
#endif
#ifdef Q_OS_LINUX
inline std::atomic_bool linux_wake_error = false;
inline std::atomic_int linux_add_watch_successes_before_failure = -1;
inline std::atomic_int linux_add_watch_successes_before_pause = -1;
inline std::atomic_bool linux_add_watch_pause_reached = false;
inline std::atomic_bool linux_add_watch_pause_released = false;
inline std::atomic_bool linux_pause_watch_publication_requested = false;
inline std::atomic_bool linux_watch_publication_pause_reached = false;
inline std::atomic_bool linux_watch_publication_pause_released = true;
#endif
#ifdef Q_OS_MACOS
inline std::atomic_bool macos_defer_delivery = false;
#endif

} // namespace vnm::filesystem_observation::detail::native_test_hooks
#endif
