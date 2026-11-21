#include "vnm_direct_native_backend_p.h"
#include "vnm_native_event_decode_p.h"
#include "vnm_native_test_hooks_p.h"
#include "vnm_windows_directory_identity_p.h"

#include <QDir>
#include <QByteArray>
#include <QScopeGuard>
#include <QtLogging>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <utility>

namespace vnm::filesystem_observation::detail {
namespace {

constexpr size_t k_buffer_bytes = 64 * 1024;
constexpr DWORD k_notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME |
    FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES |
    FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
    FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY;

QString windows_error(const char* operation, DWORD error)
{
    return QStringLiteral("%1 failed (Windows error %2)")
        .arg(QString::fromLatin1(operation)).arg(error);
}

using Read_extended = BOOL (WINAPI *)(HANDLE, LPVOID, DWORD, BOOL, DWORD,
    LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE,
    READ_DIRECTORY_NOTIFY_INFORMATION_CLASS);

Read_extended read_extended()
{
    static const auto function = reinterpret_cast<Read_extended>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadDirectoryChangesExW"));
    return function;
}

bool unsupported_extended(DWORD error)
{
    return error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED;
}

struct Registration
{
    const uint64_t id;
    QString path;
    HANDLE directory = INVALID_HANDLE_VALUE;
    OVERLAPPED overlapped{};
    alignas(FILE_NOTIFY_INFORMATION) std::array<char, k_buffer_bytes> buffer{};
    bool retiring = false;
    bool awaiting_rearm = false;
    bool extended = read_extended() != nullptr;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    bool retirement_completion_held = false;
#endif
};

bool use_basic_notifications(Registration& registration, HANDLE port,
    std::unique_lock<std::mutex>& lock)
{
    // Maintenance owns this completed request. Reopening and checking its
    // identity must not hold the lock used by the other native completions.
    lock.unlock();
    const auto relock = qScopeGuard([&] {
        if (!lock.owns_lock()) {
            const DWORD error = GetLastError();
            lock.lock();
            SetLastError(error);
        }
    });
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    if (native_test_hooks::windows_pause_basic_recovery_requested.exchange(false)) {
        native_test_hooks::windows_basic_recovery_pause_reached.store(true);
        native_test_hooks::windows_basic_recovery_pause_released.wait(false);
    }
    const DWORD open_error = native_test_hooks::windows_open_error.load();
    if (open_error != ERROR_SUCCESS) {
        SetLastError(open_error);
        return false;
    }
#endif
    const std::wstring native_path = QDir::toNativeSeparators(registration.path).toStdWString();
    const HANDLE current = CreateFileW(native_path.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (current == INVALID_HANDLE_VALUE) {
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    if (!windows_directory_handles_match(registration.directory, current)) {
        const DWORD error = GetLastError();
        CloseHandle(current);
        SetLastError(error == ERROR_SUCCESS ? ERROR_FILE_INVALID : error);
        return false;
    }
    if (!CreateIoCompletionPort(current, port, reinterpret_cast<ULONG_PTR>(&registration), 0)) {
        const DWORD error = GetLastError();
        CloseHandle(current);
        SetLastError(error);
        return false;
    }
    lock.lock();
    // The kernel retains notification records in the handle's original format.
    // No request is pending here. Close that buffer before arming a fresh handle
    // in the other format, retaining the same registration and user buffer.
    CloseHandle(registration.directory);
    registration.directory = current;
    registration.extended = false;
    return true;
}

bool queue_read(Registration& registration, HANDLE port, std::unique_lock<std::mutex>& lock,
    bool recover_format)
{
    // Logical directory interests share recursive physical anchors on Windows.
    // Opening each descendant would prevent renaming its containing directory.
    registration.overlapped = {};
    if (registration.extended) {
        DWORD error = ERROR_SUCCESS;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        error = native_test_hooks::windows_extended_read_error.load();
#endif
        if (error == ERROR_SUCCESS) {
            if (read_extended()(registration.directory, registration.buffer.data(),
                    static_cast<DWORD>(registration.buffer.size()), TRUE, k_notify_filter,
                    nullptr, &registration.overlapped, nullptr, ReadDirectoryNotifyExtendedInformation))
            {
                return true;
            }
            error = GetLastError();
        }
        if (!unsupported_extended(error) || !recover_format) {
            SetLastError(error);
            return false;
        }
        if (!use_basic_notifications(registration, port, lock)) {
            return false;
        }
        registration.overlapped = {};
    }
    return ReadDirectoryChangesW(registration.directory,
        registration.buffer.data(), static_cast<DWORD>(registration.buffer.size()),
        TRUE, k_notify_filter, nullptr, &registration.overlapped, nullptr) != FALSE;
}

} // namespace

struct Direct_native_backend::Impl
{
    // Only the registry worker creates the port; wake() reads its publication.
    // A failed allocation is retried by the registry's bounded arm schedule.
    std::atomic<HANDLE> port = nullptr;
    mutable std::mutex m_mutex;
    std::map<uint64_t, std::unique_ptr<Registration>> registrations;
    std::atomic_bool wake_pending = false;
    std::atomic_uint64_t kernel_overflows = 0;
    std::atomic_uint64_t decoder_budget_losses = 0;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    bool shutting_down = false;

    bool release_held_retirements()
    {
        if (native_test_hooks::windows_held_retirement_count.load() == 0 ||
            (!shutting_down && native_test_hooks::windows_hold_retired_completions.load()))
        {
            return false;
        }
        bool released = false;
        for (auto position = registrations.begin(); position != registrations.end();) {
            if (!position->second->retirement_completion_held) {
                ++position;
                continue;
            }
            CloseHandle(position->second->directory);
            position = registrations.erase(position);
            --native_test_hooks::windows_held_retirement_count;
            released = true;
        }
        return released;
    }
#endif
};

Direct_native_backend::Direct_native_backend()
    : m_impl(std::make_unique<Impl>())
{}

Direct_native_backend::~Direct_native_backend()
{
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    m_impl->shutting_down = true;
#endif
    // Cancellation requests do not relinquish OS ownership of OVERLAPPED or the
    // buffer. Keep every retired allocation until its completion is dequeued.
    for (auto it = m_impl->registrations.begin(); it != m_impl->registrations.end();) {
        auto& registration = *it->second;
        if (registration.awaiting_rearm) {
            CloseHandle(registration.directory);
            it = m_impl->registrations.erase(it);
        }
        else {
            registration.retiring = true;
            CancelIoEx(registration.directory, &registration.overlapped);
            ++it;
        }
    }
    while (!m_impl->registrations.empty()) {
        wait(std::chrono::milliseconds(INFINITE));
    }
    if (const HANDLE port = m_impl->port.load()) {
        CloseHandle(port);
    }
}

bool Direct_native_backend::arm(uint64_t registration, const QString& directory, QString& error)
{
    error.clear();
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    ++native_test_hooks::registration_attempts;
    const DWORD arm_error = native_test_hooks::windows_arm_error.load();
    if (arm_error != ERROR_SUCCESS) {
        error = windows_error("CreateFileW", arm_error);
        return false;
    }
    const DWORD open_error = native_test_hooks::windows_open_error.load();
    if (open_error != ERROR_SUCCESS) {
        error = windows_error("CreateFileW", open_error);
        return false;
    }
#endif
    HANDLE port = m_impl->port.load();
    if (!port) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        const DWORD port_error = native_test_hooks::windows_completion_port_error.load();
        if (port_error != ERROR_SUCCESS) {
            error = windows_error("CreateIoCompletionPort", port_error);
            return false;
        }
#endif
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        if (!port) {
            error = windows_error("CreateIoCompletionPort", GetLastError());
            return false;
        }
        m_impl->port.store(port);
    }
    auto operation = std::make_unique<Registration>(Registration{registration, directory});
    operation->path.detach();
    operation->path.squeeze();
    const std::wstring native_path = QDir::toNativeSeparators(directory).toStdWString();
    operation->directory = CreateFileW(native_path.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (operation->directory == INVALID_HANDLE_VALUE) {
        error = windows_error("CreateFileW", GetLastError());
        return false;
    }
    if (!windows_directory_handles_match(operation->directory, operation->directory)) {
        error = windows_error("Directory identity", GetLastError());
        CloseHandle(operation->directory);
        return false;
    }
    // Opening and checking filesystem identity can block on a remote volume.
    // Existing native operations keep draining throughout those admission probes.
    std::unique_lock lock(m_impl->m_mutex);
    if (m_impl->registrations.contains(registration)) {
        error = QStringLiteral("Native registration ID is still allocated");
        CloseHandle(operation->directory);
        return false;
    }
    // The key points at a retained operation carrying an immutable full-width ID;
    // it never points at a registry slot that could be reused after cancellation.
    if (!CreateIoCompletionPort(operation->directory, port,
            reinterpret_cast<ULONG_PTR>(operation.get()), 0))
    {
        error = windows_error("CreateIoCompletionPort association", GetLastError());
        CloseHandle(operation->directory);
        return false;
    }
    const auto position = m_impl->registrations.emplace(registration, std::move(operation)).first;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    if (native_test_hooks::windows_pause_before_first_arm_requested.exchange(false)) {
        lock.unlock();
        native_test_hooks::windows_first_arm_pause_reached.store(true);
        native_test_hooks::windows_first_arm_pause_reached.notify_all();
        native_test_hooks::windows_first_arm_pause_released.wait(false);
        lock.lock();
    }
#endif
    if (!queue_read(*position->second, port, lock, true)) {
        error = windows_error("Directory notification request", GetLastError());
        CloseHandle(position->second->directory);
        m_impl->registrations.erase(position);
        return false;
    }
    return true;
}

void Direct_native_backend::retire(uint64_t registration)
{
    const std::lock_guard lock(m_impl->m_mutex);
    const auto found = m_impl->registrations.find(registration);
    if (found == m_impl->registrations.end() || found->second->retiring) {
        return;
    }
    found->second->retiring = true;
    if (found->second->awaiting_rearm) {
        CloseHandle(found->second->directory);
        m_impl->registrations.erase(found);
        return;
    }
    CancelIoEx(found->second->directory, &found->second->overlapped);
}

bool Direct_native_backend::resume(uint64_t registration, QString& error)
{
    std::unique_lock lock(m_impl->m_mutex);
    const auto found = m_impl->registrations.find(registration);
    if (found == m_impl->registrations.end()) {
        error = QStringLiteral("Directory registration was retired before recovery");
        return false;
    }
    auto& operation = *found->second;
    Q_ASSERT(operation.awaiting_rearm);
    const HANDLE port = m_impl->port.load();
    if (!use_basic_notifications(operation, port, lock) || !queue_read(operation, port, lock, true)) {
        error = windows_error("Basic notification recovery", GetLastError());
        CloseHandle(operation.directory);
        m_impl->registrations.erase(found);
        return false;
    }
    operation.awaiting_rearm = false;
    return true;
}

bool Direct_native_backend::retirement_pending(uint64_t registration) const
{
    const std::lock_guard lock(m_impl->m_mutex);
    const auto found = m_impl->registrations.find(registration);
    return found != m_impl->registrations.end() && found->second->retiring;
}

bool Direct_native_backend::identity_matches(uint64_t registration) const
{
    QString path;
    HANDLE retained = INVALID_HANDLE_VALUE;
    {
        const std::lock_guard lock(m_impl->m_mutex);
        const auto found = m_impl->registrations.find(registration);
        if (found == m_impl->registrations.end() || found->second->retiring) {
            return false;
        }
        path = found->second->path;
        if (!DuplicateHandle(GetCurrentProcess(), found->second->directory,
                GetCurrentProcess(), &retained, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            return false;
        }
    }
    const auto close_retained = qScopeGuard([&] { CloseHandle(retained); });
    const std::wstring native_path = QDir::toNativeSeparators(path).toStdWString();
    const HANDLE current = CreateFileW(native_path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (current == INVALID_HANDLE_VALUE) {
        return false;
    }
    const bool matches = windows_directory_handles_match(retained, current);
    CloseHandle(current);
    return matches;
}

Native_wait_result Direct_native_backend::wait(std::chrono::milliseconds timeout)
{
    Native_wait_result result;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    {
        const std::lock_guard lock(m_impl->m_mutex);
        if (m_impl->release_held_retirements()) {
            result.capacity_changed = true;
            return result;
        }
    }
#endif
    // Posting an IOCP wake can fail, and no port exists before the first arm.
    // Retain a bounded wait so shutdown can recover from either case.
    if (timeout == std::chrono::milliseconds::max()) {
        timeout = std::chrono::milliseconds(100);
    }
    const DWORD milliseconds = static_cast<DWORD>(std::clamp<int64_t>(
        timeout.count(), 0, INFINITE));
    const HANDLE port = m_impl->port.load();
    if (!port) {
        Sleep(milliseconds);
        return {};
    }
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    OVERLAPPED* overlapped = nullptr;
    BOOL completed = GetQueuedCompletionStatus(port,
        &bytes, &key, &overlapped, milliseconds);
    DWORD error = completed ? ERROR_SUCCESS : GetLastError();
    std::unique_lock lock(m_impl->m_mutex);
    if (!overlapped) {
        if (completed) {
            m_impl->wake_pending.store(false);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            result.capacity_changed = m_impl->release_held_retirements();
#endif
        }
        else
        if (error != WAIT_TIMEOUT) {
            qFatal("Filesystem observation completion port failed: %lu", error);
        }
        return result;
    }
    auto* operation = reinterpret_cast<Registration*>(key);
    const uint64_t id = operation->id;
    if (operation->retiring) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (!m_impl->shutting_down && native_test_hooks::windows_hold_retired_completions.load()) {
            // The OS completion is real and dequeued. Keep its resources owned
            // without blocking delivery for other registrations on the port.
            operation->retirement_completion_held = true;
            ++native_test_hooks::windows_held_retirement_count;
            return {};
        }
#endif
        CloseHandle(operation->directory);
        m_impl->registrations.erase(id);
        result.capacity_changed = true;
        return result;
    }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    const DWORD forced_error = native_test_hooks::windows_completion_error.exchange(ERROR_SUCCESS);
    if (forced_error != ERROR_SUCCESS) {
        completed = FALSE;
        error = forced_error;
    }
    if (native_test_hooks::windows_zero_detail_completion.exchange(false)) {
        bytes = 0;
    }
#endif
    Direct_change change;
    change.registration = id;
    change.batch.root = operation->path;
    change.batch.scope = operation->path;
    QByteArray detail;
    const bool extended_detail = operation->extended;
    if (!completed && operation->extended && unsupported_extended(error)) {
        mark_native_rescan(change.batch,
            windows_error("Extended notifications unsupported; using basic notifications", error));
        operation->awaiting_rearm = change.rearm_required = true;
    }
    else
    if (!completed || bytes == 0 || bytes > operation->buffer.size()) {
        const bool overflow = error == ERROR_NOTIFY_ENUM_DIR || (completed && bytes == 0);
        if (overflow) {
            ++m_impl->kernel_overflows;
        }
        mark_native_rescan(change.batch,
            completed ? QStringLiteral("Windows notification detail was lost")
                      : windows_error("ReadDirectoryChangesW completion", error),
            overflow ? Native_reason::QUEUE_OVERFLOW : Native_reason::COVERAGE_CHANGED);
        // Overflow loses detail, not the handle. Rearm the same registration and
        // retain the mandatory enumeration, including changes between requests.
        change.coverage_lost = !overflow;
    }
    else {
        // Copy the completed bytes before reusing the OS-owned buffer. Decode
        // only after reissue, outside the lock needed by arm and cancellation.
        detail = QByteArray(operation->buffer.data(), bytes);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::native_notifications;
#endif
    }
    if (change.coverage_lost) {
        // Recovery is the registry's responsibility; returning a lost registration
        // must not leave a hidden armed operation consuming its replacement budget.
        CloseHandle(operation->directory);
        m_impl->registrations.erase(id);
    }
    else
    if (!change.rearm_required) {
        if (!queue_read(*operation, port, lock, false)) {
            const DWORD rearm_error = GetLastError();
            if (operation->extended && unsupported_extended(rearm_error)) {
                operation->awaiting_rearm = change.rearm_required = true;
                mark_native_rescan(change.batch,
                    QStringLiteral("Extended notifications unavailable; basic recovery required"));
            }
            else {
                // A failed rearm is the current failure even if missing detail
                // already required reconciliation on this completed request.
                change.batch.diagnostic = windows_error("Directory notification rearm", rearm_error);
                change.batch.reason = Native_reason::REGISTRATION_FAILED;
                mark_native_rescan(change.batch, change.batch.diagnostic,
                    change.batch.reason);
                change.coverage_lost = true;
                CloseHandle(operation->directory);
                m_impl->registrations.erase(id);
            }
        }
    }
    lock.unlock();
    if (!detail.isEmpty()) {
        auto decoded = extended_detail
            ? decode_windows_extended_notifications(change.batch.root, detail.constData(), detail.size())
            : decode_windows_notifications(change.batch.root, detail.constData(), detail.size());
        if (decoded.budget_exceeded) {
            ++m_impl->decoder_budget_losses;
        }
        if (change.batch.rescan_required) {
            mark_native_rescan(decoded.batch, change.batch.diagnostic, change.batch.reason);
            if (change.coverage_lost) {
                decoded.batch.reason = change.batch.reason;
                decoded.batch.diagnostic = change.batch.diagnostic;
            }
        }
        change.batch = std::move(decoded.batch);
    }
    result.capacity_changed = change.coverage_lost;
    result.changes.append(std::move(change));
    return result;
}

void Direct_native_backend::wake()
{
    const HANDLE port = m_impl->port.load();
    if (!port || m_impl->wake_pending.exchange(true)) {
        return;
    }
    DWORD error = ERROR_SUCCESS;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    error = native_test_hooks::windows_wake_error.load();
#endif
    if (error == ERROR_SUCCESS) {
        if (PostQueuedCompletionStatus(port, 0, 0, nullptr)) {
            return;
        }
        error = GetLastError();
    }
    m_impl->wake_pending.store(false);
    // The native wait remains bounded so a failed post cannot strand
    // shutdown. Registry commands retain their own handoff wake.
    qWarning("Filesystem observation wake failed: %lu", error);
}

size_t Direct_native_backend::allocated_registrations() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    return m_impl->registrations.size();
}

size_t Direct_native_backend::allocated_bytes() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    size_t bytes = 0;
    for (const auto& [id, registration] : m_impl->registrations) {
        bytes += registration_bytes(registration->path);
    }
    return bytes;
}

native_loss_counts_t Direct_native_backend::loss_counts() const
{
    return {m_impl->kernel_overflows.load(), m_impl->decoder_budget_losses.load()};
}

size_t Direct_native_backend::registration_bytes(const QString& directory)
{
    // Include the OS notification buffer associated with each open handle, plus
    // conservative allocator/map-node overhead and the owned UTF-16 path.
    return sizeof(Registration) + k_buffer_bytes + 256 +
        (static_cast<size_t>(directory.size()) + 1) * sizeof(QChar);
}

} // namespace vnm::filesystem_observation::detail
