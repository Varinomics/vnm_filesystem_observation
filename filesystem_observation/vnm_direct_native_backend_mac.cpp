#include "vnm_direct_native_backend_p.h"
#include "vnm_native_event_decode_p.h"
#include "vnm_native_test_hooks_p.h"
#include "vnm_path_name.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMap>

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>
#include <sys/stat.h>

#include <atomic>
#include <condition_variable>
#include <map>
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

bool contains_path(const QString& ancestor, const QString& path)
{
    return path == ancestor || path.startsWith(ancestor.endsWith(QLatin1Char('/'))
        ? ancestor : ancestor + QLatin1Char('/'));
}

constexpr uint32_t k_dropped = kFSEventStreamEventFlagUserDropped |
    kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagEventIdsWrapped;
constexpr uint32_t k_root_lost = kFSEventStreamEventFlagRootChanged |
    kFSEventStreamEventFlagUnmount;

} // namespace

Native_decode_result decode_macos_notifications(
    const QString& root, const QString& native_root,
    size_t count, const char* const* paths, const uint32_t* flags,
    const uint64_t* ids, uint64_t baseline)
{
    Native_decode_result result;
    auto& batch = result.batch;
    bool coverage_lost = false;
    for (size_t index = 0; index != count; ++index) {
        const uint32_t flag = flags[index];
        if (flag & kFSEventStreamEventFlagEventIdsWrapped) {
            // The former sequence no longer orders future events. Keep the
            // loss signal and let reconciliation cover the wrap boundary.
            baseline = 0;
        }
        if (ids[index] <= baseline && !(flag & (k_dropped | k_root_lost))) {
            continue;
        }
        if (flag & k_dropped) {
            mark_native_rescan(batch, QStringLiteral("FSEvents lost event detail"),
                Native_reason::QUEUE_OVERFLOW);
        }
        if (flag & k_root_lost) {
            coverage_lost = true;
            mark_native_rescan(batch, QStringLiteral("FSEvents directory registration changed"),
                Native_reason::COVERAGE_CHANGED);
        }
        const QString native_path = path_name::normalized(QFile::decodeName(paths[index]));
        if ((flag & (kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagMount)) &&
            contains_path(native_path, native_root))
        {
            mark_native_rescan(batch, QStringLiteral("FSEvents requires directory reconciliation"));
        }
        if ((flag & (kFSEventStreamEventFlagItemRenamed | kFSEventStreamEventFlagItemRemoved)) &&
            contains_path(native_path, native_root))
        {
            // A shared ancestor stream reports a logical root move as file
            // detail, including an intermediate ancestor moving away and back.
            coverage_lost = true;
            mark_native_rescan(batch, QStringLiteral("FSEvents directory path changed"),
                Native_reason::COVERAGE_CHANGED);
            continue;
        }
        const bool is_root = native_path == native_root;
        const bool is_child = QFileInfo(native_path).path() == native_root;
        if (!is_root && !is_child) {
            continue;
        }
        if (flag & (kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagMount)) {
            mark_native_rescan(batch, QStringLiteral("FSEvents requires directory reconciliation"));
        }
        if (flag & (k_dropped | k_root_lost | kFSEventStreamEventFlagHistoryDone)) {
            continue;
        }
        Event event;
        event.path = is_root ? root : path_name::normalized(
            QDir(root).filePath(QFileInfo(native_path).fileName()));
        if (flag & kFSEventStreamEventFlagItemIsDir) {
            event.entry_type = Entry_type::DIRECTORY;
        }
        else
        if (flag & (kFSEventStreamEventFlagItemIsFile | kFSEventStreamEventFlagItemIsSymlink)) {
            event.entry_type = Entry_type::NON_DIRECTORY;
        }
        if (flag & kFSEventStreamEventFlagItemRenamed) {
            // FSEvents identifies a changed endpoint, not its old/new orientation.
            // Keep that endpoint and let complete_native_batch retain reconciliation.
            event.kind = Event_kind::RENAMED;
        }
        else
        if (flag & kFSEventStreamEventFlagItemRemoved) {
            event.kind = Event_kind::REMOVED;
        }
        else
        if (flag & kFSEventStreamEventFlagItemCreated) {
            event.kind = Event_kind::CREATED;
        }
        if ((flag & kFSEventStreamEventFlagItemCreated) &&
            (flag & kFSEventStreamEventFlagItemRemoved))
        {
            const bool paths_complete = !batch.rescan_required || batch.rescan_event_paths_complete;
            mark_native_rescan(batch, QStringLiteral("FSEvents coalesced entry replacement"));
            // The entry's sequence is ambiguous, but every endpoint is this path.
            batch.rescan_event_paths_complete = paths_complete;
        }
        result.budget_exceeded |= !append_native_event(batch, std::move(event));
    }
    if (batch.events.isEmpty() && !batch.rescan_required) {
        return {};
    }
    if (coverage_lost) {
        batch.reason = Native_reason::COVERAGE_CHANGED;
    }
    batch = complete_native_batch(std::move(batch), root, 0);
    return result;
}

struct Direct_native_backend::Impl
{
    struct Stream;
    struct Registration
    {
        uint64_t                id;
        QString                 path;
        QString                 native_path;
        identity_t              identity;
        uint64_t                baseline = 0;
        std::shared_ptr<Stream>  stream;
    };

    struct Stream
    {
        Impl* owner;
        QString native_path;
        identity_t identity;
        FSEventStreamRef handle = nullptr;
        bool started = false;
        bool coverage_lost = false;
        std::map<uint64_t, Registration*> registrations;
        QMultiMap<QString, Registration*> paths;

        void add(Registration& registration)
        {
            registrations.emplace(registration.id, &registration);
            paths.insert(registration.native_path, &registration);
        }

        void remove(uint64_t id)
        {
            const auto found = registrations.find(id);
            if (found != registrations.end()) {
                paths.remove(found->second->native_path, found->second);
                registrations.erase(found);
            }
        }

        ~Stream()
        {
            if (handle) {
                if (started) {
                    FSEventStreamStop(handle);
                }
                FSEventStreamInvalidate(handle);
                // The callback context and its registration pointers remain
                // alive until every already queued callback has returned.
                dispatch_sync_f(owner->m_queue, nullptr, [](void*) {});
                FSEventStreamRelease(handle);
            }
        }
    };

    dispatch_queue_t m_queue = nullptr;
    std::map<uint64_t, Registration> m_registrations;
    std::mutex m_mutex;
    std::condition_variable m_ready;
    QMap<uint64_t, Direct_change> m_pending;
    std::atomic_uint64_t m_kernel_overflows = 0;
    std::atomic_uint64_t m_decoder_budget_losses = 0;
    bool m_awakened = false;

    ~Impl()
    {
        while (!m_registrations.empty()) {
            remove(m_registrations.begin()->first);
        }
        if (m_queue) {
            dispatch_release(m_queue);
        }
    }

    void remove(uint64_t id)
    {
        std::shared_ptr<Stream> retired;
        {
            const std::lock_guard lock(m_mutex);
            const auto found = m_registrations.find(id);
            if (found == m_registrations.end()) {
                return;
            }
            retired = found->second.stream;
            retired->remove(id);
            m_registrations.erase(found);
            m_pending.remove(id);
        }
        // Last-client retirement may drain callbacks that need m_mutex.
    }

    static void receive(
        ConstFSEventStreamRef, void* context, size_t count, void* paths,
        const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[])
    {
        auto& stream = *static_cast<Stream*>(context);
        auto& owner = *stream.owner;
        const std::lock_guard lock(owner.m_mutex);
        std::map<uint64_t, Registration*> affected;
        const auto include = [&](const QString& path) {
            const auto range = stream.paths.equal_range(path);
            for (auto it = range.first; it != range.second; ++it) {
                affected.emplace(it.value()->id, it.value());
            }
        };
        for (size_t index = 0; index != count; ++index) {
            if (flags[index] & (kFSEventStreamEventFlagUserDropped | kFSEventStreamEventFlagKernelDropped)) {
                ++owner.m_kernel_overflows;
            }
            if (flags[index] & (k_dropped | k_root_lost)) {
                stream.coverage_lost |= (flags[index] & k_root_lost) != 0;
                affected = stream.registrations;
                continue;
            }
            const QString path = path_name::normalized(
                QFile::decodeName(static_cast<const char* const*>(paths)[index]));
            if ((flags[index] & (kFSEventStreamEventFlagItemRenamed | kFSEventStreamEventFlagItemRemoved)) &&
                contains_path(path, stream.native_path))
            {
                stream.coverage_lost = true;
            }
            include(path);
            include(QFileInfo(path).path());
            if (flags[index] & (kFSEventStreamEventFlagItemRenamed | kFSEventStreamEventFlagItemRemoved |
                    kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagMount))
            {
                const QString prefix = path.endsWith(QLatin1Char('/')) ? path : path + QLatin1Char('/');
                for (auto it = stream.paths.lowerBound(prefix);
                     it != stream.paths.end() && it.key().startsWith(prefix); ++it)
                {
                    affected.emplace(it.value()->id, it.value());
                }
            }
        }
        bool decoder_budget_exceeded = false;
        for (const auto& [id, pointer] : affected) {
            auto& registration = *pointer;
            auto decoded = decode_macos_notifications(registration.path, registration.native_path,
                count, static_cast<const char* const*>(paths), flags, ids, registration.baseline);
            decoder_budget_exceeded |= decoded.budget_exceeded;
            auto& batch = decoded.batch;
            for (size_t index = 0; index != count; ++index) {
                if (flags[index] & kFSEventStreamEventFlagEventIdsWrapped) {
                    registration.baseline = 0;
                }
            }
            if (batch.root.isEmpty()) {
                continue;
            }
            auto& change = owner.m_pending[id];
            change.registration = id;
            change.coverage_lost |= batch.reason == Native_reason::COVERAGE_CHANGED;
            if (change.batch.root.isEmpty()) {
                change.batch = std::move(batch);
            }
            else {
                if (batch.rescan_required) {
                    const bool paths_complete = batch.rescan_event_paths_complete &&
                        (!change.batch.rescan_required || change.batch.rescan_event_paths_complete);
                    mark_native_rescan(change.batch, batch.diagnostic, batch.reason);
                    change.batch.rescan_event_paths_complete = paths_complete;
                }
                for (auto& event : batch.events) {
                    decoder_budget_exceeded |= !append_native_event(change.batch, std::move(event));
                }
                change.batch = complete_native_batch(std::move(change.batch), registration.path, 0);
            }
        }
        // One callback may fan out to aliases and descendant registrations.
        // Attribute its decoding loss before those copies reach the native drain.
        if (decoder_budget_exceeded) {
            ++owner.m_decoder_budget_losses;
        }
        owner.m_ready.notify_one();
    }
};

Direct_native_backend::Direct_native_backend()
:
    m_impl(std::make_unique<Impl>())
{}

Direct_native_backend::~Direct_native_backend() = default;

bool Direct_native_backend::arm(uint64_t registration, const QString& directory, QString& error)
{
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    ++native_test_hooks::registration_attempts;
#endif
    auto& d = *m_impl;
    const auto identity = directory_identity(directory);
    const QString native_path = QFileInfo(directory).canonicalFilePath();
    if (!identity || native_path.isEmpty()) {
        error = QStringLiteral("Directory is absent or its identity is unavailable");
        return false;
    }
    if (!d.m_queue) {
        d.m_queue = dispatch_queue_create("com.varinomics.filesystem-observation", DISPATCH_QUEUE_SERIAL);
        if (!d.m_queue) {
            error = QStringLiteral("FSEvents dispatch queue unavailable");
            return false;
        }
    }
    std::shared_ptr<Impl::Stream> stream;
    for (const auto& [id, existing] : d.m_registrations) {
        if (contains_path(existing.stream->native_path, native_path) &&
            directory_identity(existing.stream->native_path) ==
                std::optional<identity_t>(existing.stream->identity))
        {
            const std::lock_guard lock(d.m_mutex);
            if (!existing.stream->coverage_lost) {
                stream = existing.stream;
                break;
            }
        }
    }
    const bool new_stream = !stream;
    if (new_stream) {
        stream = std::make_shared<Impl::Stream>();
        stream->owner = &d;
        stream->native_path = native_path;
        stream->identity = *identity;
    }
    Impl::Registration* record;
    {
        const std::lock_guard lock(d.m_mutex);
        auto [iterator, inserted] = d.m_registrations.emplace(registration,
            Impl::Registration{registration, directory, native_path, *identity, 0, stream});
        Q_ASSERT(inserted);
        record = &iterator->second;
        stream->add(*record);
    }
    if (new_stream) {
        const CFStringRef path = native_path.toCFString();
        const void* path_values[] = {path};
        const CFArrayRef paths = CFArrayCreate(kCFAllocatorDefault, path_values, 1, &kCFTypeArrayCallBacks);
        FSEventStreamContext context{0, stream.get(), nullptr, nullptr, nullptr};
        // A concrete event ID permits FlushSync even when this stream receives no
        // events; SinceNow can trigger a CarbonCore soft assertion in that case.
        const FSEventStreamEventId since = FSEventsGetCurrentEventId();
        CFTimeInterval latency = 0.025;
        FSEventStreamCreateFlags flags = kFSEventStreamCreateFlagFileEvents |
            kFSEventStreamCreateFlagWatchRoot | kFSEventStreamCreateFlagNoDefer;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (native_test_hooks::macos_defer_delivery.load()) {
            latency = 60;
            flags &= ~kFSEventStreamCreateFlagNoDefer;
        }
#endif
        stream->handle = FSEventStreamCreate(kCFAllocatorDefault, &Impl::receive, &context,
            paths, since, latency, flags);
        CFRelease(paths);
        CFRelease(path);
        if (!stream->handle) {
            d.remove(registration);
            error = QStringLiteral("FSEvents stream allocation failed");
            return false;
        }
        FSEventStreamSetDispatchQueue(stream->handle, d.m_queue);
        stream->started = FSEventStreamStart(stream->handle);
        if (!stream->started) {
            d.remove(registration);
            error = QStringLiteral("FSEvents stream registration failed");
            return false;
        }
    }
    std::map<Impl::Stream*, std::shared_ptr<Impl::Stream>> retired;
    if (new_stream) {
        const std::lock_guard lock(d.m_mutex);
        for (auto& [id, existing] : d.m_registrations) {
            if (!stream->coverage_lost && existing.stream != stream &&
                contains_path(native_path, existing.stream->native_path))
            {
                // Start the broader stream before withdrawing narrower coverage.
                // Both may deliver during the handoff; existing pending detail stays.
                retired.emplace(existing.stream.get(), existing.stream);
                existing.stream = stream;
                stream->add(existing);
            }
        }
    }
    // Older streams may hold events preceding the broader stream's starting ID.
    // Deliver those native buffers while their existing logical clients still live.
    for (const auto& [handle, previous] : retired) {
        FSEventStreamFlushSync(previous->handle);
    }
    // History and live delivery can repeat IDs across FlushSync. Establish a
    // sequence cutoff before the registry's initial directory/readback capture.
    FSEventStreamFlushSync(stream->handle);
    dispatch_sync_f(d.m_queue, record, [](void* context) {
        auto& registration = *static_cast<Impl::Registration*>(context);
        auto& owner = *registration.stream->owner;
        const std::lock_guard lock(owner.m_mutex);
        registration.baseline = FSEventsGetCurrentEventId();
        const auto pending = owner.m_pending.find(registration.id);
        // Initial readback covers content before the cutoff, but cannot restore
        // a stream whose root registration was lost while arming.
        if (pending != owner.m_pending.end() && !pending->coverage_lost) {
            owner.m_pending.erase(pending);
        }
    });
    retired.clear();
    bool coverage_lost;
    {
        const std::lock_guard lock(d.m_mutex);
        coverage_lost = stream->coverage_lost;
    }
    if (coverage_lost || !identity_matches(registration)) {
        retire(registration);
        error = QStringLiteral("Directory coverage changed while arming");
        return false;
    }
    return true;
}

void Direct_native_backend::retire(uint64_t registration)
{
    m_impl->remove(registration);
}

bool Direct_native_backend::identity_matches(uint64_t registration) const
{
    const auto found = m_impl->m_registrations.find(registration);
    return found != m_impl->m_registrations.end() &&
        directory_identity(found->second.path) == std::optional<identity_t>(found->second.identity) &&
        directory_identity(found->second.native_path) == std::optional<identity_t>(found->second.identity);
}

Native_wait_result Direct_native_backend::wait(std::chrono::milliseconds timeout)
{
    auto& d = *m_impl;
    QMap<uint64_t, Direct_change> pending;
    {
        std::unique_lock lock(d.m_mutex);
        const auto ready = [&] { return d.m_awakened || !d.m_pending.isEmpty(); };
        if (timeout == std::chrono::milliseconds::max()) {
            d.m_ready.wait(lock, ready);
        }
        else {
            d.m_ready.wait_for(lock, timeout, ready);
        }
        d.m_awakened = false;
        pending.swap(d.m_pending);
    }
    Native_wait_result output;
    for (auto& change : pending) {
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
    const std::lock_guard lock(m_impl->m_mutex);
    m_impl->m_awakened = true;
    m_impl->m_ready.notify_one();
}

size_t Direct_native_backend::allocated_registrations() const
{
    return m_impl->m_registrations.size();
}

size_t Direct_native_backend::allocated_bytes() const
{
    size_t bytes = 0;
    for (const auto& [id, registration] : m_impl->m_registrations) {
        bytes += registration_bytes(registration.path);
    }
    return bytes;
}

native_loss_counts_t Direct_native_backend::loss_counts() const
{
    return {m_impl->m_kernel_overflows.load(), m_impl->m_decoder_budget_losses.load()};
}

size_t Direct_native_backend::registration_bytes(const QString& directory)
{
    // Keep registry admission conservative: a logical directory reserves room
    // for its own stream even when an existing ancestor supplies native coverage.
    return 65536 + 4096 + size_t(directory.size()) * sizeof(QChar) * 2;
}

} // namespace vnm::filesystem_observation::detail
