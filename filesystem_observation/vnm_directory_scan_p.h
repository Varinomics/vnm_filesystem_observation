#pragma once

#include "vnm_path_name.h"

#include <QString>
#include <QStringList>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace vnm::filesystem_observation::detail {

inline constexpr size_t k_directory_scan_result_bytes = 4 * 1024 * 1024;

struct Directory_scan_request
{
    uint64_t id = 0;
    uint64_t owner = 0;
    // Retain the owner's memory charge until queued/running/result work drains.
    std::shared_ptr<void> retention;
    std::shared_ptr<void> job_charge;
    QString root;
    QString directory;
    std::function<bool(const QString&, const QString&)> filter;
    std::shared_ptr<std::atomic_bool> active;
    std::shared_ptr<path_name::Policy_epoch> policy;
    bool bounded_workload = true;
};

size_t directory_plan_key_bytes(const path_name::Key& key);
size_t directory_plan_policy_bytes(const QString& path);
size_t directory_scan_job_bytes(const QString& root, const QString& directory);

struct Directory_candidate
{
    QString path;
    path_name::Key key;
    std::shared_ptr<path_name::Policy_epoch> policy;
};

struct Directory_scan_result
{
    uint64_t id = 0;
    std::shared_ptr<void> retention;
    std::shared_ptr<void> job_charge;
    std::shared_ptr<path_name::Policy_epoch> policy;
    QList<Directory_candidate> directories;
    size_t bytes = 256;
    QString error;
    bool complete = false;
    bool filter_pending = false;
};

// Each turn enumerates a bounded part of one directory. Native dispatch never
// enumerates, and one wide directory cannot monopolize the pending scan queue.
class Directory_scanner
{
public:
    using Callback = std::function<void(Directory_scan_result)>;

    Directory_scanner(size_t workers, Callback callback);
    ~Directory_scanner();
    Directory_scanner(const Directory_scanner&) = delete;
    Directory_scanner& operator=(const Directory_scanner&) = delete;

    bool submit(Directory_scan_request request, QString& error);
    void cancel(uint64_t owner);
    void stop();
    std::pair<size_t, size_t> resource_counts() const;

private:
    struct Impl;
    std::shared_ptr<Impl> m_impl;
};

} // namespace vnm::filesystem_observation::detail
