#include "vnm_directory_scan_p.h"
#include "vnm_filesystem_native_watcher.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QScopeGuard>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <exception>
#include <mutex>
#include <new>
#include <optional>
#include <unordered_map>
#include <thread>
#include <system_error>
#include <utility>
#include <vector>

namespace vnm::filesystem_observation::detail {
namespace {

std::filesystem::path native_path(const QString& path)
{
#ifdef Q_OS_WIN
    return std::filesystem::path(path.toStdWString());
#else
    return std::filesystem::path(QFile::encodeName(path).toStdString());
#endif
}

QString display_path(const std::filesystem::path& path)
{
#ifdef Q_OS_WIN
    return path_name::normalized(QString::fromStdWString(path.native()));
#else
    return path_name::normalized(QFile::decodeName(path.native().c_str()));
#endif
}

} // namespace

size_t directory_plan_key_bytes(const path_name::Key& key)
{
    const auto text_bytes = [](const QString& text) {
        return size_t(64) + size_t(text.capacity() + 1) * sizeof(QChar);
    };
    size_t bytes = sizeof(key) + 64 + text_bytes(key.root.spelling) +
        size_t(key.components.capacity()) * sizeof(path_name::Key_component);
    for (const auto& component : key.components) {
        bytes += text_bytes(component.spelling);
    }
    return bytes;
}

size_t directory_plan_policy_bytes(const QString& path)
{
    // A private node snapshot owns only its named parent prefixes, including
    // the directory's own child-name decision. Charge map/allocator overhead
    // and text independently of Qt's implicit sharing.
    size_t bytes = sizeof(path_name::Policy_epoch) + 512;
    for (qsizetype index = 0; index <= path.size(); ++index) {
        if (index == path.size() || path[index] == QChar('/')) {
            bytes += 128 + size_t(index + 2) * sizeof(QChar);
        }
    }
    return bytes;
}

size_t directory_scan_job_bytes(const QString& root, const QString& directory)
{
    // The allowance includes the directory stream's platform buffer, request,
    // queue/all-map nodes, iterator and worker-local spelling. Every submission
    // owns this charge separately, including canceled predecessors still draining.
    return 64 * 1024 + sizeof(Directory_scan_request) +
        sizeof(std::filesystem::directory_iterator) + 512 +
        size_t(root.capacity() + 3 * directory.capacity() + 4) * sizeof(QChar) +
        directory_plan_policy_bytes(directory);
}

struct Directory_scanner::Impl
{
    struct Job
    {
        Directory_scan_request request;
        std::optional<std::filesystem::directory_iterator> iterator;
        QString next;
        std::shared_ptr<path_name::Policy_epoch> policy;
        std::thread::id caller;
    };

    Impl(size_t worker_limit, Callback callback)
    :
        worker_limit(worker_limit),
        callback(std::move(callback))
    {}

    void run()
    {
        for (;;) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock lock(mutex);
                changed.wait(lock, [&] { return stopped || !jobs.empty(); });
                if (stopped) {
                    return;
                }
                job = std::move(jobs.front());
                jobs.pop_front();
                job->caller = std::this_thread::get_id();
            }
            Directory_scan_result result;
            result.id = job->request.id;
            result.retention = job->request.retention;
            result.job_charge = job->request.job_charge;
            if (!job->request.active->load()) {
                result.complete = true;
            }
            else
            if (!job->iterator) {
                const QFileInfo directory(job->request.directory);
                const bool linked_descendant = (directory.isSymLink() || directory.isJunction()) &&
                    !job->request.policy->same(job->request.directory, job->request.root);
                if (!directory.isDir() || linked_descendant || !directory.isReadable()) {
                    result.error = QStringLiteral("Directory expansion is unavailable: %1")
                        .arg(job->request.directory);
                    result.complete = true;
                }
                else {
                    std::error_code error;
                    job->iterator.emplace(native_path(job->request.directory), error);
                    if (error) {
                        result.error = QString::fromStdString(error.message());
                        result.complete = true;
                    }
                }
            }
            if (!result.complete && !job->policy) {
                try {
                    const auto path = job->request.directory + QStringLiteral("/_");
                    job->policy = job->request.policy->fork_for_paths(
                        {path}, directory_plan_policy_bytes(job->request.directory),
                        nullptr, job->request.bounded_workload);
                }
                catch (const std::exception& failure) {
                    result.error = QString::fromLocal8Bit(failure.what());
                    result.complete = true;
                }
            }
            result.policy = job->policy;
            qsizetype characters = 0;
            for (int examined = 0; !result.complete && examined != 128; ++examined) {
                if (!job->request.active->load()) {
                    result.complete = true;
                    break;
                }
                if (job->next.isEmpty()) {
                    if (*job->iterator == std::filesystem::directory_iterator{}) {
                        result.complete = true;
                        break;
                    }
                    const auto entry = **job->iterator;
                    std::error_code error;
                    const auto status = entry.symlink_status(error);
                    const auto path = display_path(entry.path());
                    if (error || std::filesystem::is_directory(status)) {
                        const QFileInfo child(path);
                        // Windows can report a junction as a directory or report its
                        // missing target. Recursive expansion skips descendant links.
                        if (child.isSymLink() || child.isJunction()) {
                            error.clear();
                        }
                        else
                        if (!error) {
                            job->next = path;
                        }
                    }
                    if (!error) {
                        job->iterator->increment(error);
                    }
                    if (error) {
                        result.error = QString::fromStdString(error.message());
                        result.complete = true;
                        break;
                    }
                    if (job->next.isEmpty()) {
                        continue;
                    }
                }
                if (!result.directories.isEmpty() && characters + job->next.size() > 32768) {
                    break;
                }
                try {
                    const auto& path = job->next;
                    if (path.size() > 32768) {
                        result.error = QStringLiteral("Directory expansion path text budget exhausted");
                        result.complete = true;
                        break;
                    }
                    if (!job->request.filter || job->request.filter(job->request.root, path)) {
                        if (job->request.bounded_workload &&
                            directory_plan_policy_bytes(path) > k_directory_scan_result_bytes / 2)
                        {
                            result.error = QStringLiteral("Directory policy snapshot memory budget exhausted");
                            result.complete = true;
                            break;
                        }
                        auto policy = job->policy->fork_for_paths(
                            {path + QStringLiteral("/_")}, directory_plan_policy_bytes(path),
                            nullptr, job->request.bounded_workload);
                        auto key = policy->key(path);
                        const size_t bytes = sizeof(Directory_candidate) + 64 +
                            size_t(path.capacity() + 1) * sizeof(QChar) + directory_plan_key_bytes(key) +
                            directory_plan_policy_bytes(path);
                        if (job->request.bounded_workload && bytes > k_directory_scan_result_bytes - 256) {
                            result.error = QStringLiteral("Directory expansion result memory budget exhausted");
                            result.complete = true;
                            break;
                        }
                        if (!result.directories.isEmpty() && result.bytes + bytes > 64 * 1024) {
                            break;
                        }
                        characters += path.size();
                        result.bytes += bytes;
                        result.directories.append({path, std::move(key), std::move(policy)});
                    }
                    job->next.clear();
                }
                catch (const Directory_filter_pending&) {
                    result.filter_pending = true;
                    result.complete = true;
                }
                catch (const std::exception& failure) {
                    result.error = QString::fromLocal8Bit(failure.what());
                    result.complete = true;
                }
                catch (...) {
                    result.error = QStringLiteral("Directory eligibility evaluation failed");
                    result.complete = true;
                }
            }
            const bool complete = result.complete;
            if (job->request.active->load()) {
                callback(std::move(result));
            }
            {
                std::lock_guard lock(mutex);
                job->caller = {};
                if (complete || !job->request.active->load()) {
                    --pending;
                    all.erase(job->request.id);
                }
                else
                if (!stopped) {
                    jobs.push_back(std::move(job));
                    changed.notify_one();
                }
                changed.notify_all();
            }
        }
    }

    std::mutex mutex;
    std::condition_variable changed;
    std::deque<std::shared_ptr<Job>> jobs;
    std::unordered_map<uint64_t, std::shared_ptr<Job>> all;
    std::vector<std::thread> workers;
    size_t worker_limit;
    size_t pending = 0;
    Callback callback;
    bool stopped = false;
};

Directory_scanner::Directory_scanner(size_t workers, Callback callback)
:
    m_impl(std::make_shared<Impl>(workers, std::move(callback)))
{
}

Directory_scanner::~Directory_scanner() { stop(); }

bool Directory_scanner::submit(Directory_scan_request request, QString& error)
{
    std::lock_guard lock(m_impl->mutex);
    if (m_impl->stopped) {
        error = QStringLiteral("Directory expansion owner has stopped");
        return false;
    }
    while (m_impl->workers.size() < m_impl->worker_limit) {
        try {
            m_impl->workers.emplace_back([state = m_impl] { state->run(); });
        }
        catch (const std::system_error& failure) {
            error = QString::fromLocal8Bit(failure.what());
            break;
        }
    }
    if (m_impl->workers.empty()) {
        if (error.isEmpty()) {
            error = QStringLiteral("Directory expansion worker budget exhausted");
        }
        return false;
    }
    auto job = std::make_shared<Impl::Job>();
    job->request = std::move(request);
    const auto position = m_impl->all.emplace(job->request.id, job).first;
    auto discard = qScopeGuard([&] { m_impl->all.erase(position); });
    m_impl->jobs.push_back(std::move(job));
    discard.dismiss();
    ++m_impl->pending;
    m_impl->changed.notify_one();
    return true;
}

void Directory_scanner::cancel(uint64_t owner)
{
    std::unique_lock lock(m_impl->mutex);
    for (const auto& [id, job] : m_impl->all) {
        if (job->request.owner == owner) {
            job->request.active->store(false);
        }
    }
    const auto self = std::this_thread::get_id();
    m_impl->changed.notify_all();
    m_impl->changed.wait(lock, [&] {
        return std::all_of(m_impl->all.cbegin(), m_impl->all.cend(), [&](const auto& item) {
            const auto& job = item.second;
            return job->request.owner != owner || job->caller == std::thread::id{} || job->caller == self;
        });
    });
}
std::pair<size_t, size_t> Directory_scanner::resource_counts() const
{
    const std::lock_guard lock(m_impl->mutex);
    return {m_impl->pending, m_impl->workers.size()};
}

void Directory_scanner::stop()
{
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->stopped = true;
        for (const auto& [id, job] : m_impl->all) {
            job->request.active->store(false);
        }
        m_impl->changed.notify_all();
    }
    for (auto& worker : m_impl->workers) {
        if (!worker.joinable()) {
            continue;
        }
        if (worker.get_id() == std::this_thread::get_id()) {
            worker.detach();
        }
        else {
            worker.join();
        }
    }
}

} // namespace vnm::filesystem_observation::detail
