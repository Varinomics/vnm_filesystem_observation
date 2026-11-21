#pragma once

#include "vnm_filesystem_native_event.h"
#include "vnm_filesystem_native_watcher.h"
#include "vnm_path_name.h"

#include <QList>
#include <QString>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace vnm::filesystem_observation::detail {

struct direct_limits_t
{
    size_t registrations = 4096;
    size_t bytes = 64 * 1024 * 1024;
    size_t scan_workers = 1;
    size_t plan_bytes = 8 * 1024 * 1024;
    bool bounded_workload = true;
};

class Direct_registry
{
public:
    using Callback = std::function<void(const Native_batch&)>;

    explicit Direct_registry(direct_limits_t limits = {});
    ~Direct_registry();
    Direct_registry(const Direct_registry&) = delete;
    Direct_registry& operator=(const Direct_registry&) = delete;

    uint64_t attach(Callback callback);
    // Called by the existing registration worker, never by the scheduler. Return
    // after each requested root has been attempted, including incomplete arming.
    void replace(uint64_t client, const QList<Watch_spec>& paths, Watch_mode mode,
        std::shared_ptr<path_name::Policy_epoch> policy,
        Native_watcher::Directory_filter filter, bool wait_for_expansion,
        uint64_t eligibility_generation = 0);
    void detach(uint64_t client);
    // Read coherent published coverage without entering the maintenance graph.
    // Known loss is published before native retirement and before its delivery.
    bool covers(uint64_t client, const QString& path) const;
    Coverage_status coverage_status(uint64_t client, const QString& path) const;
    uint64_t revision(uint64_t client, const QString& path) const;
    Resource_counts resource_counts() const;

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    enum class Maintenance_stage { INGEST, RECONCILE, RETIREMENT, SCAN_APPLIED };
    void set_maintenance_observer_for_tests(std::function<void(Maintenance_stage)> observer,
        uint64_t exercise_client = 0);
    struct Maintenance_counts
    {
        uint64_t identity_candidates = 0;
        uint64_t binding_candidates = 0;
        uint64_t resource_nodes = 0;
        uint64_t read_summary_nodes = 0;
    };
    Maintenance_counts maintenance_counts_for_tests(uint64_t client) const;
    bool maintenance_pending_for_tests() const;
    QStringList armed_directories_for_tests() const;
    QStringList covered_logical_directories_for_tests() const;
    bool set_directory_available_for_tests(const QString& path, bool available);
    void invalidate_content_for_tests(uint64_t client);
    void inject_overflow_for_tests(uint64_t client);
    int expansion_count_for_tests(uint64_t client) const;
    void set_expansion_observer_for_tests(uint64_t client,
        std::function<void(Native_watcher::Expansion_stage)> observer);
    void set_coverage_for_tests(uint64_t client, const QString& path, bool covered);
#endif

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

} // namespace vnm::filesystem_observation::detail
