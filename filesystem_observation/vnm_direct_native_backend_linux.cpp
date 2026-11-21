#include "vnm_direct_native_backend_p.h"
#include "vnm_native_event_decode_p.h"
#include "vnm_native_test_hooks_p.h"
#include "vnm_path_name.h"

#include <QDir>
#include <QFile>
#include <QMap>
#include <QSet>

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace vnm::filesystem_observation::detail {
namespace {

struct identity_t
{
    dev_t device;
    ino_t inode;
    bool operator==(const identity_t&) const = default;
};

std::optional<identity_t> directory_identity(const QString& path)
{
    struct stat value {};
    if (stat(QFile::encodeName(path).constData(), &value) != 0 || !S_ISDIR(value.st_mode)) {
        return std::nullopt;
    }
    return identity_t{value.st_dev, value.st_ino};
}

constexpr uint32_t k_mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB |
    IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF |
    IN_UNMOUNT | IN_ONLYDIR;

int create_wake_descriptor()
{
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    if (native_test_hooks::linux_wake_error.load()) {
        errno = EMFILE;
        return -1;
    }
#endif
    return eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

class Inotify_instance
{
public:
    Inotify_instance()
    :
        m_descriptor(inotify_init1(IN_CLOEXEC | IN_NONBLOCK))
    {}

    ~Inotify_instance()
    {
        if (m_descriptor >= 0) {
            close(m_descriptor);
        }
    }

    Inotify_instance(const Inotify_instance&) = delete;
    Inotify_instance& operator=(const Inotify_instance&) = delete;

    int descriptor() const { return m_descriptor; }

private:
    int m_descriptor;
};

} // namespace

struct Direct_native_backend::Impl
{
    struct Registration
    {
        QString path;
        identity_t identity;
        int descriptor;
    };

    std::mutex m_mutex;
    std::shared_ptr<Inotify_instance> m_instance;
    bool m_admitting = false;
    bool m_admission_detail_lost = false;
    QSet<int> m_admission_lost_watches;
    std::atomic_int wake_descriptor = -1;
    QMap<uint64_t, Registration> registrations;
    QMap<int, QSet<uint64_t>> users;
    QSet<int> retiring;
    QList<Direct_change> pending;
    bool m_capacity_changed = false;
    std::atomic_uint64_t kernel_overflows = 0;
    std::atomic_uint64_t decoder_budget_losses = 0;

    ~Impl()
    {
        if (wake_descriptor.load() >= 0) {
            close(wake_descriptor.load());
        }
    }

    void invalidate(const QString& reason)
    {
        m_capacity_changed |= !registrations.isEmpty() || !retiring.isEmpty();
        for (auto it = registrations.cbegin(); it != registrations.cend(); ++it) {
            Direct_change change;
            change.registration = it.key();
            change.batch.root = change.batch.scope = it->path;
            change.batch.rescan_required = true;
            change.batch.reason = Native_reason::COVERAGE_CHANGED;
            change.batch.diagnostic = reason;
            change.coverage_lost = true;
            pending.append(std::move(change));
        }
        registrations.clear();
        users.clear();
        retiring.clear();
        m_instance.reset();
    }

    Native_wait_result take_pending()
    {
        return {std::exchange(pending, {}), std::exchange(m_capacity_changed, false)};
    }
};

Direct_native_backend::Direct_native_backend()
:
    m_impl(std::make_unique<Impl>())
{
    // A normal drain must be wakeable before its first registration, including
    // when shutdown is its first command. Failed creation keeps a finite wait.
    m_impl->wake_descriptor.store(create_wake_descriptor());
}

Direct_native_backend::~Direct_native_backend() = default;

bool Direct_native_backend::arm(uint64_t registration, const QString& directory, QString& error)
{
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    ++native_test_hooks::registration_attempts;
#endif
    auto& d = *m_impl;
    const auto identity = directory_identity(directory);
    if (!identity) {
        error = QStringLiteral("Directory is absent or its identity is unavailable");
        return false;
    }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    auto allowed = native_test_hooks::linux_add_watch_successes_before_failure.load();
    while (allowed >= 0) {
        if (allowed == 0) {
            error = QStringLiteral("inotify registration failed: injected watch exhaustion");
            return false;
        }
        if (native_test_hooks::linux_add_watch_successes_before_failure.compare_exchange_weak(allowed, allowed - 1)) {
            break;
        }
    }
#endif
    std::shared_ptr<Inotify_instance> instance;
    {
        std::unique_lock lock(d.m_mutex);
        if (d.wake_descriptor.load() < 0) {
            const int wake_descriptor = create_wake_descriptor();
            if (wake_descriptor < 0) {
                error = QStringLiteral("Native wake descriptor unavailable: %1")
                    .arg(QString::fromLocal8Bit(strerror(errno)));
                return false;
            }
            d.wake_descriptor.store(wake_descriptor);
        }
        if (!d.m_instance) {
            auto created = std::make_shared<Inotify_instance>();
            if (created->descriptor() < 0) {
                error = QStringLiteral("inotify instance unavailable: %1")
                    .arg(QString::fromLocal8Bit(strerror(errno)));
                return false;
            }
            d.m_instance = std::move(created);
        }
        instance = d.m_instance;
        d.m_admitting = true;
        d.m_admission_detail_lost = false;
        d.m_admission_lost_watches.clear();
        lock.unlock();
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        auto before_pause = native_test_hooks::linux_add_watch_successes_before_pause.load();
        while (before_pause >= 0) {
            if (before_pause == 0) {
                native_test_hooks::linux_add_watch_pause_reached.store(true);
                native_test_hooks::linux_add_watch_pause_reached.notify_all();
                native_test_hooks::linux_add_watch_pause_released.wait(false);
                native_test_hooks::linux_add_watch_successes_before_pause.store(-1);
                break;
            }
            if (native_test_hooks::linux_add_watch_successes_before_pause.compare_exchange_weak(
                    before_pause, before_pause - 1))
            {
                break;
            }
        }
#endif
        // Admission may wait for a remote filesystem or automount. Control
        // calls are serialized, while the drain keeps reading existing watches.
        const int wd = inotify_add_watch(
            instance->descriptor(), QFile::encodeName(directory).constData(), k_mask);
        const int watch_error = errno;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (native_test_hooks::linux_pause_watch_publication_requested.exchange(false)) {
            native_test_hooks::linux_watch_publication_pause_reached.store(true);
            native_test_hooks::linux_watch_publication_pause_released.wait(false);
        }
#endif
        lock.lock();
        d.m_admitting = false;
        if (d.m_instance != instance) {
            error = QStringLiteral("inotify instance was lost while arming");
            return false;
        }
        if (wd < 0) {
            error = QStringLiteral("inotify registration failed: %1")
                .arg(QString::fromLocal8Bit(strerror(watch_error)));
            return false;
        }
        if (d.retiring.contains(wd)) {
            // A reused descriptor cannot inherit unread notifications from its former
            // identity. Replacing the instance invalidates every affected capture.
            d.invalidate(QStringLiteral("inotify descriptor reused before retirement completed"));
            wake();
            error = QStringLiteral("inotify descriptor identity requires reconciliation");
            return false;
        }
        if (d.m_admission_lost_watches.contains(wd)) {
            // Aliases share a kernel watch. An unrelated ignored notification
            // cannot invalidate it, and an admission never owns its other users.
            if (!d.users.contains(wd) && inotify_rm_watch(instance->descriptor(), wd) == 0) {
                d.retiring.insert(wd);
            }
            error = QStringLiteral("Directory registration was lost before publication");
            return false;
        }
        d.registrations.insert(registration, {directory, *identity, wd});
        d.users[wd].insert(registration);
        if (d.m_admission_detail_lost) {
            // The newly created wd may have been drained before its users were
            // published. Existing watches keep flowing; this admission retains
            // the missing interval as a source-wide reconciliation obligation.
            Direct_change change;
            change.registration = registration;
            change.batch.root = change.batch.scope = directory;
            mark_native_rescan(change.batch,
                QStringLiteral("Native detail was drained during watch admission"));
            d.pending.append(std::move(change));
        }
    }
    wake();
    if (directory_identity(directory) != identity) {
        retire(registration);
        error = QStringLiteral("Directory identity changed while arming");
        return false;
    }
    {
        const std::lock_guard lock(d.m_mutex);
        if (d.m_instance != instance || !d.registrations.contains(registration)) {
            error = QStringLiteral("Directory registration was lost while arming");
            return false;
        }
    }
    return true;
}

void Direct_native_backend::retire(uint64_t registration)
{
    auto& d = *m_impl;
    const std::lock_guard lock(d.m_mutex);
    const auto found = d.registrations.find(registration);
    if (found == d.registrations.end()) {
        return;
    }
    const int wd = found->descriptor;
    d.registrations.erase(found);
    d.m_capacity_changed = true;
    auto users = d.users.find(wd);
    users->remove(registration);
    if (users->isEmpty()) {
        d.users.erase(users);
        if (inotify_rm_watch(d.m_instance->descriptor(), wd) == 0) {
            d.retiring.insert(wd);
        }
    }
    wake();
}

bool Direct_native_backend::identity_matches(uint64_t registration) const
{
    auto& d = *m_impl;
    Impl::Registration observed;
    {
        const std::lock_guard lock(d.m_mutex);
        const auto found = d.registrations.constFind(registration);
        if (found == d.registrations.cend()) {
            return false;
        }
        observed = *found;
    }
    if (directory_identity(observed.path) != std::optional<identity_t>(observed.identity)) {
        return false;
    }
    const std::lock_guard lock(d.m_mutex);
    const auto found = d.registrations.constFind(registration);
    return
        found != d.registrations.cend()       &&
        found->path       == observed.path   &&
        found->identity   == observed.identity &&
        found->descriptor == observed.descriptor;
}

Native_wait_result Direct_native_backend::wait(std::chrono::milliseconds timeout)
{
    auto& d = *m_impl;
    std::shared_ptr<Inotify_instance> instance;
    int wake_descriptor = -1;
    {
        const std::lock_guard lock(d.m_mutex);
        if (!d.pending.isEmpty() || d.m_capacity_changed) {
            return d.take_pending();
        }
        instance = d.m_instance;
        wake_descriptor = d.wake_descriptor.load();
    }
    // Holding the instance keeps its fd alive while arm() or invalidation replaces
    // the current source. Readiness for that retired instance cannot reach new users.
    std::array<pollfd, 2> descriptors{{
        {wake_descriptor, POLLIN, 0},
        {instance ? instance->descriptor() : -1, POLLIN, 0},
    }};
    if (wake_descriptor < 0) {
        timeout = std::min(timeout, std::chrono::milliseconds(100));
    }
    const int wait_ms = timeout == std::chrono::milliseconds::max() ? -1 :
        int(std::clamp(timeout.count(), std::chrono::milliseconds::rep(0),
            std::chrono::milliseconds::rep(std::numeric_limits<int>::max())));
    const int result     = poll(descriptors.data(), descriptors.size(), wait_ms);
    const int poll_error = errno;
    std::unique_lock lock(d.m_mutex);
    if (instance != d.m_instance) {
        return d.take_pending();
    }
    if (result < 0) {
        if (poll_error != EINTR) {
            d.invalidate(QStringLiteral("inotify polling failed"));
        }
        return d.take_pending();
    }
    if (descriptors[0].revents & POLLIN) {
        uint64_t wake_count;
        const auto ignored = read(wake_descriptor, &wake_count, sizeof(wake_count));
        (void)ignored;
    }
    if (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        d.invalidate(QStringLiteral("inotify instance lost"));
        return d.take_pending();
    }
    if (!(descriptors[1].revents & POLLIN)) {
        return d.take_pending();
    }
    alignas(inotify_event) std::array<char, 65536> bytes;
    const auto count = read(instance->descriptor(), bytes.data(), bytes.size());
    if (count < 0) {
        if (errno != EAGAIN && errno != EINTR) {
            d.invalidate(QStringLiteral("inotify read failed"));
        }
        return d.take_pending();
    }
    d.m_admission_detail_lost |= d.m_admitting && count > 0;
    struct Rename_endpoints
    {
        QString from;
        QString to;
    };
    QMap<std::pair<int, uint32_t>, Rename_endpoints> renames;
    for (size_t offset = 0; offset + sizeof(inotify_event) <= size_t(count);) {
        const auto& native = *reinterpret_cast<const inotify_event*>(bytes.data() + offset);
        offset += sizeof(inotify_event) + native.len;
        if (offset > size_t(count)) {
            break;
        }
        if (native.cookie == 0 || native.len == 0 ||
            !(native.mask & (IN_MOVED_FROM | IN_MOVED_TO)))
        {
            continue;
        }
        auto& endpoints = renames[{native.wd, native.cookie}];
        if (native.mask & IN_MOVED_FROM) {
            endpoints.from = QFile::decodeName(native.name);
        }
        else {
            endpoints.to = QFile::decodeName(native.name);
        }
    }
    QMap<uint64_t, Direct_change> changes;
    bool decoder_budget_exceeded = false;
    for (size_t offset = 0; offset + sizeof(inotify_event) <= (size_t)count;) {
        const auto& native = *reinterpret_cast<const inotify_event*>(bytes.data() + offset);
        offset += sizeof(inotify_event) + native.len;
        if (offset > (size_t)count) {
            d.invalidate(QStringLiteral("Truncated inotify notification"));
            break;
        }
        if (native.mask & IN_Q_OVERFLOW) {
            ++d.kernel_overflows;
            for (auto it = d.registrations.cbegin(); it != d.registrations.cend(); ++it) {
                auto& change = changes[it.key()];
                change.registration = it.key();
                change.batch.root = change.batch.scope = it->path;
                change.batch.rescan_required = true;
                change.batch.reason = Native_reason::QUEUE_OVERFLOW;
                change.batch.diagnostic = QStringLiteral("inotify queue overflow");
            }
            continue;
        }
        if (d.m_admitting && (native.mask & IN_IGNORED)) {
            d.m_admission_lost_watches.insert(native.wd);
        }
        if (native.mask & IN_IGNORED && d.retiring.remove(native.wd)) {
            d.m_capacity_changed = true;
            continue;
        }
        const auto users = d.users.value(native.wd);
        for (const auto id : users) {
            const auto& registration = d.registrations[id];
            auto& change = changes[id];
            change.registration = id;
            change.batch.root = change.batch.scope = registration.path;
            if (native.mask & (IN_IGNORED | IN_UNMOUNT | IN_DELETE_SELF | IN_MOVE_SELF)) {
                change.coverage_lost = true;
                change.batch.rescan_required = true;
                change.batch.reason = Native_reason::COVERAGE_CHANGED;
                change.batch.diagnostic = QStringLiteral("Directory registration lost its identity");
            }
            if (native.mask & (IN_IGNORED | IN_UNMOUNT)) {
                continue;
            }
            const auto path = native.len == 0 ? registration.path :
                path_name::normalized(QDir(registration.path).filePath(QFile::decodeName(native.name)));
            Event event;
            event.path = path;
            event.entry_type = native.len == 0 || (native.mask & IN_ISDIR)
                ? Entry_type::DIRECTORY : Entry_type::NON_DIRECTORY;
            if (native.mask & (IN_MOVED_FROM | IN_MOVE_SELF | IN_MOVED_TO)) {
                event.kind = Event_kind::RENAMED;
                const auto endpoints = renames.value({native.wd, native.cookie});
                if (!endpoints.from.isEmpty() && !endpoints.to.isEmpty()) {
                    if (native.mask & IN_MOVED_FROM) {
                        continue;
                    }
                    event.old_path = path_name::normalized(QDir(registration.path).filePath(endpoints.from));
                }
                else {
                    if (native.mask & (IN_MOVED_FROM | IN_MOVE_SELF)) {
                        event.old_path = std::exchange(event.path, {});
                    }
                    // Completion retains this known endpoint as a path-scoped
                    // reconciliation obligation; bounded local pairing never guesses.
                }
            }
            else
            if (native.mask & (IN_DELETE | IN_DELETE_SELF)) {
                event.kind = Event_kind::REMOVED;
            }
            else
            if (native.mask & IN_CREATE) {
                event.kind = Event_kind::CREATED;
            }
            decoder_budget_exceeded |= !append_native_event(change.batch, std::move(event));
        }
        if (native.mask & IN_IGNORED) {
            d.m_capacity_changed |= !users.isEmpty();
            for (const auto id : users) {
                d.registrations.remove(id);
            }
            d.users.remove(native.wd);
        }
    }
    // One read may fan out to aliases or independent registrations. Attribute
    // its decoding loss once, independently of those logical copies.
    if (decoder_budget_exceeded) {
        ++d.decoder_budget_losses;
    }
    auto output = d.take_pending();
    lock.unlock();
    for (auto& change : changes) {
        const auto root = change.batch.root;
        change.batch = complete_native_batch(std::move(change.batch), root, 0);
        output.changes.append(std::move(change));
    }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    if (!output.changes.isEmpty()) {
        ++native_test_hooks::native_notifications;
    }
#endif
    return output;
}

void Direct_native_backend::wake()
{
    const uint64_t value = 1;
    ssize_t result;
    do {
        result = write(m_impl->wake_descriptor.load(), &value, sizeof(value));
    }
    while (result < 0 && errno == EINTR);
    // EAGAIN means an earlier wake is still pending. The descriptor stays
    // owned until the drain joins; absent descriptors use the finite fallback.
}

size_t Direct_native_backend::allocated_registrations() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    return m_impl->registrations.size() + m_impl->retiring.size();
}

size_t Direct_native_backend::allocated_bytes() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    size_t bytes = m_impl->retiring.size() * 4096;
    for (const auto& registration : m_impl->registrations) {
        bytes += registration_bytes(registration.path);
    }
    return bytes;
}

native_loss_counts_t Direct_native_backend::loss_counts() const
{
    return {m_impl->kernel_overflows.load(), m_impl->decoder_budget_losses.load()};
}

size_t Direct_native_backend::registration_bytes(const QString& directory)
{
    return 4096 + size_t(directory.size()) * sizeof(QChar) * 2;
}

} // namespace vnm::filesystem_observation::detail
