#include "vnm_filesystem_native_watcher.h"
#include "vnm_direct_registry_p.h"
#include "vnm_direct_native_backend_p.h"
#include "vnm_direct_native_drain_p.h"
#include "vnm_native_event_decode_p.h"
#include "vnm_native_test_hooks_p.h"
#include "vnm_filesystem_observation.h"

#include <QDir>
#include <QDebug>
#include <QSemaphore>
#include <QScopeGuard>
#include <QSet>
#include <QStorageInfo>
#include <QFile>
#include <QStringList>
#include <QTemporaryDir>
#include <QtTest>

#ifdef Q_OS_WIN
#include "vnm_windows_directory_identity_p.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#ifdef Q_OS_LINUX
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#ifdef Q_OS_MACOS
#include <CoreServices/CoreServices.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstring>
#include <algorithm>
#include <cstddef>
#include <chrono>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

using namespace vnm::filesystem_observation;

namespace {

class Native_capture
{
public:
    void receive(const Native_batch& batch)
    {
        const std::lock_guard lock(m_mutex);
        m_batches.append(batch);
        m_ready.notify_all();
    }

    bool wait_for(const std::function<bool(const QList<Native_batch>&)>& predicate)
    {
        std::unique_lock lock(m_mutex);
        return m_ready.wait_for(lock, std::chrono::seconds(5), [&] {
            return predicate(m_batches);
        });
    }

    qsizetype count()
    {
        const std::lock_guard lock(m_mutex);
        return m_batches.size();
    }

    QString diagnostics()
    {
        const std::lock_guard lock(m_mutex);
        QStringList messages;
        for (const auto& batch : m_batches) {
            if (!batch.diagnostic.isEmpty() && !messages.contains(batch.diagnostic)) {
                messages.append(batch.diagnostic);
            }
        }
        return messages.join(QStringLiteral("; "));
    }

    void report_batches(const char* label)
    {
        const std::lock_guard lock(m_mutex);
        for (const auto& batch : m_batches) {
            qWarning().noquote()
                << label << "root=" << batch.root << "scope=" << batch.scope
                << "revision=" << batch.coverage_revision << "reason=" << int(batch.reason)
                << "rescan=" << batch.rescan_required
                << "paths_complete=" << batch.rescan_event_paths_complete
                << "initial=" << batch.initial_admission_only
                << "consumer_only=" << batch.consumer_reconciliation_only
                << "diagnostic=" << batch.diagnostic;
            for (const auto& event : batch.events) {
                qWarning().noquote()
                    << label << "event path=" << event.path << "old_path=" << event.old_path
                    << "kind=" << int(event.kind) << "entry_type=" << int(event.entry_type);
            }
        }
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_ready;
    QList<Native_batch> m_batches;
};

bool write_file(const QString& path, const QByteArray& contents = QByteArray("observed\n"))
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(contents) == contents.size();
}

#ifdef Q_OS_WIN
struct Windows_extended_record
{
    DWORD action;
    QString name;
    DWORD attributes;
};

QByteArray windows_extended_records(const QList<Windows_extended_record>& entries)
{
    QByteArray bytes;
    constexpr size_t header_bytes = offsetof(FILE_NOTIFY_EXTENDED_INFORMATION, FileName);
    for (qsizetype index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        FILE_NOTIFY_EXTENDED_INFORMATION header{};
        header.Action = entry.action;
        header.FileAttributes = entry.attributes;
        header.FileNameLength = static_cast<DWORD>(entry.name.size() * sizeof(wchar_t));
        const DWORD record_bytes = (header_bytes + header.FileNameLength + 3) & ~3u;
        header.NextEntryOffset = index + 1 < entries.size() ? record_bytes : 0;
        const qsizetype offset = bytes.size();
        bytes.resize(offset + record_bytes);
        std::memcpy(bytes.data() + offset, &header, header_bytes);
        std::memcpy(bytes.data() + offset + header_bytes, entry.name.utf16(), header.FileNameLength);
    }
    return bytes;
}

bool local_extended_notifications_supported(const QString& path)
{
    const QStorageInfo storage(path);
    const auto native_root = QDir::toNativeSeparators(storage.rootPath()).toStdWString();
    return GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadDirectoryChangesExW") &&
        storage.fileSystemType().compare("NTFS", Qt::CaseInsensitive) == 0 &&
        GetDriveTypeW(native_root.c_str()) == DRIVE_FIXED;
}

QByteArray windows_records(const QList<std::pair<DWORD, QString>>& entries)
{
    QByteArray bytes;
    for (qsizetype index = 0; index < entries.size(); ++index) {
        const auto& [action, name] = entries[index];
        const DWORD name_bytes = static_cast<DWORD>(name.size() * sizeof(wchar_t));
        const DWORD record_bytes = (offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes + 3) & ~3u;
        const qsizetype offset = bytes.size();
        bytes.resize(offset + record_bytes);
        auto* record = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(bytes.data() + offset);
        record->Action = action;
        record->FileNameLength = name_bytes;
        record->NextEntryOffset = index + 1 < entries.size() ? record_bytes : 0;
        std::memcpy(record->FileName, name.utf16(), name_bytes);
    }
    return bytes;
}
#endif

} // namespace

class Native_watcher_tests : public QObject
{
    Q_OBJECT

private slots:
    void native_drain_quiet_wait_observes_requested_deadline()
    {
        // Issue #93 requires a quiet handoff to remain parked until its own
        // deadline: an empty native timeout supplies no consumer work.
        detail::Direct_native_drain drain;
        int early_returns = 0;
        for (int trial = 0; trial < 3; ++trial) {
            const auto started = std::chrono::steady_clock::now();
            const auto changes = drain.wait(std::chrono::milliseconds(500)).changes;
            const auto elapsed = std::chrono::steady_clock::now() - started;
            QVERIFY(changes.isEmpty());
            early_returns += elapsed < std::chrono::milliseconds(450);
            qInfo() << "quiet native handoff trial" << trial << "elapsed ms"
                    << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        }
        QCOMPARE(early_returns, 0);
    }

    void native_handoff_wakes_survive_wait_entry_data()
    {
        QTest::addColumn<bool>("native_event");
        QTest::addColumn<bool>("before_wait");
        QTest::newRow("data-before-wait")    << true  << true;
        QTest::newRow("data-after-wait")     << true  << false;
        QTest::newRow("control-before-wait") << false << true;
        QTest::newRow("control-after-wait")  << false << false;
    }

    void native_handoff_wakes_survive_wait_entry()
    {
        using namespace std::chrono_literals;
        QFETCH(bool, native_event);
        QFETCH(bool, before_wait);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto path = directory.filePath(QStringLiteral("notification.txt"));
        detail::Direct_native_drain drain;
        if (native_event) {
            QString error;
            QVERIFY2(drain.arm(1, directory.path(), error), qPrintable(error));
        }
        const auto notify = [&] {
            if (native_event) {
                return write_file(path);
            }
            drain.wake();
            return true;
        };
        if (before_wait) {
            const auto batches = drain.resource_counts().batches;
            QVERIFY(notify());
            if (native_event) {
                QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().batches > batches, 3000);
            }
        }
        const auto waits = detail::native_test_hooks::native_handoff_waits.load();
        QSemaphore returned;
        std::atomic_bool stop = false;
        bool observed = false;
        std::thread waiter([&] {
            const auto deadline = std::chrono::steady_clock::now() + 5s;
            do {
                const auto result = drain.wait(5s);
                if (!native_event) {
                    observed = result.changes.isEmpty() && !result.capacity_changed;
                    break;
                }
                observed = std::any_of(result.changes.cbegin(), result.changes.cend(), [&](const auto& change) {
                    return std::any_of(change.batch.events.cbegin(), change.batch.events.cend(),
                        [&](const auto& event) { return event.path == path; });
                });
            }
            while (!observed && !stop.load() && std::chrono::steady_clock::now() < deadline);
            returned.release();
        });
        auto finish = qScopeGuard([&] {
            stop.store(true);
            drain.wake();
            waiter.join();
        });
        if (!before_wait) {
            // The counter advances under the handoff mutex. wake() cannot take
            // that mutex until the consumer has entered its condition wait.
            QTRY_VERIFY_WITH_TIMEOUT(detail::native_test_hooks::native_handoff_waits.load() > waits, 3000);
            QVERIFY(!returned.tryAcquire());
            QVERIFY(notify());
        }
        QVERIFY(returned.tryAcquire(1, 3000));
        waiter.join();
        finish.dismiss();
        QVERIFY(observed);
    }

    void registry_quiet_waits_are_event_driven_data()
    {
        QTest::addColumn<bool>("first_registration");
        QTest::newRow("shutdown-before-registration") << false;
        QTest::newRow("first-registration")           << true;
    }

    void registry_quiet_waits_are_event_driven()
    {
        QFETCH(bool, first_registration);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto registry_threads = detail::native_test_hooks::direct_registry_threads.load();
        const auto drain_threads    = detail::native_test_hooks::native_drain_threads.load();
        {
            detail::Direct_registry registry;
            QTRY_VERIFY_WITH_TIMEOUT(!registry.maintenance_pending_for_tests(), 3000);
            const auto registry_before = detail::native_test_hooks::registry_maintenance_turns.load();
            const auto native_before   = detail::native_test_hooks::native_wait_returns.load();
            QTest::qWait(350);
            const auto registry_turns = detail::native_test_hooks::registry_maintenance_turns.load() - registry_before;
            const auto native_returns = detail::native_test_hooks::native_wait_returns.load() - native_before;
            qInfo() << "quiet registry turns" << registry_turns << "native returns" << native_returns;
            QCOMPARE(registry_turns, uint64_t(0));
#ifndef Q_OS_WIN
            QCOMPARE(native_returns, uint64_t(0));
#endif
            if (first_registration) {
                Native_capture capture;
                const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
                const auto detach = qScopeGuard([&] { registry.detach(client); });
                registry.replace(client, {{directory.path(), 0}}, Watch_mode::DIRECT,
                    std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
                QVERIFY(registry.covers(client, directory.path()));
                const auto path = directory.filePath(QStringLiteral("first-registration.txt"));
                QVERIFY(write_file(path));
                QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
                    return std::any_of(batches.cbegin(), batches.cend(), [&](const auto& batch) {
                        return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const auto& event) {
                            return event.path == path;
                        });
                    });
                }));
            }
        }
        QCOMPARE(detail::native_test_hooks::direct_registry_threads.load(), registry_threads);
        QCOMPARE(detail::native_test_hooks::native_drain_threads.load(), drain_threads);
    }

    void native_admission_continues_without_an_external_event()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QList<Watch_spec> paths;
        for (int index = 0; index < 40; ++index) {
            const auto path = directory.filePath(QStringLiteral("directory-%1").arg(index));
            QVERIFY(QDir().mkdir(path));
            paths.append({path, 0});
        }
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto detach = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, paths, Watch_mode::DIRECT,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QTRY_VERIFY_WITH_TIMEOUT(std::all_of(paths.cbegin(), paths.cend(), [&](const auto& path) {
            return registry.covers(client, path.path);
        }), 5000);
        const auto path = paths.back().path + QStringLiteral("/after-admission.txt");
        QVERIFY(write_file(path));
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const auto& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const auto& event) {
                    return event.path == path;
                });
            });
        }));
    }

    void registry_capacity_blocked_work_waits_for_retry()
    {
        using namespace std::chrono_literals;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        detail::direct_limits_t limits;
        limits.registrations = 0;
        detail::Direct_registry registry(limits);
        const auto client = registry.attach([](const Native_batch&) {});
        const auto detach = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, {{directory.path(), 0}}, Watch_mode::DIRECT,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(!registry.covers(client, directory.path()));
        QVERIFY(registry.resource_counts().failed > 0);
        QTRY_VERIFY_WITH_TIMEOUT(!registry.maintenance_pending_for_tests(), 3000);
        const auto turns_before = detail::native_test_hooks::registry_maintenance_turns.load();
        const auto started      = std::chrono::steady_clock::now();
        QTest::qWait(350);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        const auto turns   = detail::native_test_hooks::registry_maintenance_turns.load() - turns_before;
        qInfo() << "capacity-blocked registry turns" << turns;
        // Real parent, identity and native retries may fall in a delayed sample.
        // Allow those bounded passes while detecting continuously runnable work.
        const auto retry_windows = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() + 1;
        QVERIFY2(turns <= uint64_t(8 * retry_windows), "Capacity-blocked admission did not park for its retry");
    }

#if defined(Q_OS_LINUX) || defined(Q_OS_WIN)
    void native_retirement_capacity_survives_wait_entry_data()
    {
        QTest::addColumn<bool>("before_wait");
        QTest::newRow("completion-before-wait") << true;
        QTest::newRow("completion-after-wait")  << false;
    }

    void native_retirement_capacity_survives_wait_entry()
    {
        using namespace std::chrono_literals;
        QFETCH(bool, before_wait);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        detail::Direct_native_drain drain;
        QString error;
        QVERIFY2(drain.arm(1, directory.path(), error), qPrintable(error));
        if (before_wait) {
            const auto changes = detail::native_test_hooks::native_capacity_changes.load();
            drain.retire(1);
            QTRY_COMPARE_WITH_TIMEOUT(drain.allocated_registrations(), size_t(0), 3000);
            QTRY_VERIFY_WITH_TIMEOUT(detail::native_test_hooks::native_capacity_changes.load() > changes, 3000);
        }
        const auto waits = detail::native_test_hooks::native_handoff_waits.load();
        detail::Native_wait_result result;
        QSemaphore returned;
        std::thread waiter([&] {
            result = drain.wait(5s);
            returned.release();
        });
        auto finish = qScopeGuard([&] {
            drain.wake();
            waiter.join();
        });
        if (!before_wait) {
            QTRY_VERIFY_WITH_TIMEOUT(detail::native_test_hooks::native_handoff_waits.load() > waits, 3000);
            QVERIFY(!returned.tryAcquire());
            drain.retire(1);
        }
        QVERIFY(returned.tryAcquire(1, 3000));
        waiter.join();
        finish.dismiss();
        QVERIFY(result.changes.isEmpty());
        QVERIFY(result.capacity_changed);
        QTRY_COMPARE_WITH_TIMEOUT(drain.allocated_registrations(), size_t(0), 3000);
    }
#endif

#ifdef Q_OS_WIN
    void windows_failed_wake_keeps_control_and_shutdown_progress()
    {
        using namespace std::chrono_literals;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        detail::native_test_hooks::windows_wake_error.store(ERROR_NOT_ENOUGH_MEMORY);
        const auto restore = qScopeGuard([] {
            detail::native_test_hooks::windows_wake_error.store(ERROR_SUCCESS);
        });
        // arm(), the explicit control command, and destruction all reach the
        // failed-post path. The native recovery bound must keep join finite.
        for (int index = 0; index < 3; ++index) {
            QTest::ignoreMessage(QtWarningMsg, "Filesystem observation wake failed: 8");
        }
        const auto started = std::chrono::steady_clock::now();
        {
            detail::Direct_native_drain drain;
            QString error;
            QVERIFY2(drain.arm(1, directory.path(), error), qPrintable(error));
            drain.wake();
            const auto result = drain.wait(5s);
            QVERIFY(result.changes.isEmpty());
        }
        QVERIFY(std::chrono::steady_clock::now() - started < 3s);
    }

    void native_drain_continues_during_notification_format_recovery()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir first;
        QTemporaryDir second;
        QVERIFY(first.isValid() && second.isValid());
        if (!local_extended_notifications_supported(first.path())) {
            QSKIP("This filesystem does not provide extended notifications");
        }
        detail::Direct_native_drain drain;
        QString error;
        QVERIFY2(drain.arm(1, first.path(), error), qPrintable(error));
        QVERIFY2(drain.arm(2, second.path(), error), qPrintable(error));
        std::thread maintenance;
        const auto cleanup = qScopeGuard([&] {
            hooks::windows_basic_recovery_pause_released.store(true);
            hooks::windows_basic_recovery_pause_released.notify_all();
            if (maintenance.joinable()) {
                maintenance.join();
            }
            hooks::windows_pause_basic_recovery_requested.store(false);
            hooks::windows_completion_error.store(ERROR_SUCCESS);
        });
        hooks::windows_basic_recovery_pause_reached.store(false);
        hooks::windows_basic_recovery_pause_released.store(false);
        hooks::windows_pause_basic_recovery_requested.store(true);
        hooks::windows_completion_error.store(ERROR_NOT_SUPPORTED);
        QVERIFY(write_file(first.filePath(QStringLiteral("format-change.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().batches > 0, 5000);
        QList<detail::Direct_change> recovered;
        maintenance = std::thread([&] { recovered = drain.wait(std::chrono::seconds(5)).changes; });
        QTRY_VERIFY_WITH_TIMEOUT(hooks::windows_basic_recovery_pause_reached.load(), 5000);
        const auto before = drain.resource_counts().batches;
        QVERIFY(write_file(second.filePath(QStringLiteral("while-reopening.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().batches > before, 5000);
        hooks::windows_basic_recovery_pause_released.store(true);
        hooks::windows_basic_recovery_pause_released.notify_all();
        maintenance.join();
        QCOMPARE(recovered.size(), 1);
        QVERIFY(recovered[0].batch.rescan_required);
        QVERIFY(!recovered[0].coverage_lost);
    }

    void completed_format_recovery_can_retire_without_another_completion()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        if (!local_extended_notifications_supported(directory.path())) {
            QSKIP("This filesystem does not provide extended notifications");
        }
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, directory.path(), error), qPrintable(error));
        detail::native_test_hooks::windows_completion_error.store(ERROR_NOT_SUPPORTED);
        const auto cleanup = qScopeGuard([] {
            detail::native_test_hooks::windows_completion_error.store(ERROR_SUCCESS);
        });
        QVERIFY(write_file(directory.filePath(QStringLiteral("format-change.txt"))));
        const auto changes = backend.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(changes.size(), 1);
        QVERIFY(changes[0].rearm_required);
        backend.retire(1);
        QCOMPARE(backend.allocated_registrations(), size_t(0));
    }
#endif

#ifdef Q_OS_LINUX
    void native_inotify_overflow_covers_every_registration_on_the_instance()
    {
        QFile queue_limit(QStringLiteral("/proc/sys/fs/inotify/max_queued_events"));
        QVERIFY(queue_limit.open(QIODevice::ReadOnly));
        bool valid_limit = false;
        const auto maximum_events = queue_limit.readAll().trimmed().toLongLong(&valid_limit);
        QVERIFY(valid_limit && maximum_events > 0);
        QTemporaryDir first;
        QTemporaryDir second;
        QVERIFY(first.isValid() && second.isValid());
        QFile left(first.filePath(QStringLiteral("left.txt")));
        QFile right(first.filePath(QStringLiteral("right.txt")));
        QVERIFY(left.open(QIODevice::WriteOnly | QIODevice::Unbuffered));
        QVERIFY(right.open(QIODevice::WriteOnly | QIODevice::Unbuffered));
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, first.path(), error), qPrintable(error));
        QVERIFY2(backend.arm(2, second.path(), error), qPrintable(error));
        // Keep the native reader stopped. Alternating paths prevent the kernel
        // from coalescing adjacent identical events, without changing its limits.
        for (qint64 index = 0; index <= maximum_events; ++index) {
            QCOMPARE((index % 2 == 0 ? left : right).write("x", 1), qint64(1));
        }
        QSet<uint64_t> lost_sources;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (lost_sources.size() != 2 && std::chrono::steady_clock::now() < deadline) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                if (change.batch.reason != Native_reason::QUEUE_OVERFLOW) {
                    continue;
                }
                QVERIFY(change.batch.rescan_required);
                QVERIFY(!change.batch.rescan_event_paths_complete);
                QVERIFY(!change.coverage_lost);
                lost_sources.insert(change.registration);
            }
        }
        QCOMPARE(lost_sources, (QSet<uint64_t>{1, 2}));
        QCOMPARE(backend.loss_counts().kernel_overflows, uint64_t(1));
        QCOMPARE(backend.allocated_registrations(), size_t(2));
        QVERIFY(backend.identity_matches(1));
        QVERIFY(backend.identity_matches(2));
    }

    void native_decoder_loss_is_counted_once_before_alias_fanout()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, directory.path(), error), qPrintable(error));
        QVERIFY2(backend.arm(2, directory.path(), error), qPrintable(error));
        // All records fit one native read; both aliases independently exhaust
        // their decoded detail, but the source lost detail only once.
        for (int index = 0; index < 300; ++index) {
            QVERIFY(write_file(directory.filePath(QStringLiteral("f%1").arg(index))));
        }
        const auto changes = backend.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(changes.size(), 2);
        for (const auto& change : changes) {
            QVERIFY(change.batch.rescan_required);
            QVERIFY(!change.batch.rescan_event_paths_complete);
            QVERIFY(!change.coverage_lost);
            QCOMPARE(change.batch.reason, Native_reason::DETAIL_UNAVAILABLE);
        }
        QCOMPARE(backend.loss_counts().decoder_budget_losses, uint64_t(1));
        QCOMPARE(backend.loss_counts().kernel_overflows, uint64_t(0));
    }

    void native_drain_continues_during_watch_admission()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir first;
        QTemporaryDir second;
        QVERIFY(first.isValid() && second.isValid());
        detail::Direct_native_drain drain;
        QString error;
        QVERIFY2(drain.arm(1, first.path(), error), qPrintable(error));
        std::thread maintenance;
        const auto cleanup = qScopeGuard([&] {
            Native_watcher::release_linux_add_watch_pause_for_tests();
            if (maintenance.joinable()) {
                maintenance.join();
            }
            hooks::linux_add_watch_successes_before_pause.store(-1);
        });
        Native_watcher::set_linux_add_watch_pause_before_attempt_for_tests(0);
        bool armed = false;
        maintenance = std::thread([&] { armed = drain.arm(2, second.path(), error); });
        QTRY_VERIFY_WITH_TIMEOUT(hooks::linux_add_watch_pause_reached.load(), 5000);
        const auto before = drain.resource_counts().batches;
        QVERIFY(write_file(first.filePath(QStringLiteral("during-admission.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().batches > before, 5000);
        Native_watcher::release_linux_add_watch_pause_for_tests();
        maintenance.join();
        QVERIFY2(armed, qPrintable(error));
    }

    void native_alias_admission_preserves_descriptor_lifetime_data()
    {
        QTest::addColumn<bool>("remove_shared_directory");
        QTest::newRow("unrelated-orphan-retirement") << false;
        QTest::newRow("shared-watch-lost-before-publication") << true;
    }

    void native_alias_admission_preserves_descriptor_lifetime()
    {
        // Oracle: losing a different watch cannot revoke a published alias;
        // losing the shared watch cannot publish another user of a dead source.
        QFETCH(bool, remove_shared_directory);
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto original = workspace.filePath(QStringLiteral("original"));
        const auto alias    = workspace.filePath(QStringLiteral("alias"));
        const auto victim   = workspace.filePath(QStringLiteral("victim"));
        QVERIFY(QDir().mkdir(original));
        QVERIFY(QDir().mkdir(victim));
        QVERIFY(QFile::link(original, alias));
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, original, error), qPrintable(error));
        QVERIFY2(backend.arm(2, victim, error), qPrintable(error));
        if (!remove_shared_directory) {
            // Deletion removes the kernel watch before retire() runs, leaving
            // its queued IN_IGNORED without a published user or retirement.
            QVERIFY(QDir().rmdir(victim));
            backend.retire(2);
            QCOMPARE(backend.allocated_registrations(), size_t(1));
        }
        std::thread maintenance;
        const auto cleanup = qScopeGuard([&] {
            hooks::linux_watch_publication_pause_released.store(true);
            hooks::linux_watch_publication_pause_released.notify_all();
            if (maintenance.joinable()) {
                maintenance.join();
            }
            hooks::linux_pause_watch_publication_requested.store(false);
        });
        hooks::linux_watch_publication_pause_reached.store(false);
        hooks::linux_watch_publication_pause_released.store(false);
        hooks::linux_pause_watch_publication_requested.store(true);
        bool armed = false;
        maintenance = std::thread([&] { armed = backend.arm(3, alias, error); });
        QTRY_VERIFY_WITH_TIMEOUT(hooks::linux_watch_publication_pause_reached.load(), 5000);
        const auto marker = QDir(original).filePath(QStringLiteral("drain-marker.txt"));
        if (remove_shared_directory) {
            QVERIFY(QDir().rmdir(original));
        }
        else {
            QVERIFY(write_file(marker));
        }
        bool observed_drain = false;
        const auto drained = [&] {
            const auto changes = backend.wait(std::chrono::milliseconds(100)).changes;
            observed_drain |= std::any_of(changes.cbegin(), changes.cend(), [&](const auto& change) {
                if (change.registration != 1) {
                    return false;
                }
                if (remove_shared_directory) {
                    return change.coverage_lost;
                }
                return std::any_of(change.batch.events.cbegin(), change.batch.events.cend(),
                    [&](const Event& event) { return event.path == marker; });
            });
            return observed_drain;
        };
        QTRY_VERIFY_WITH_TIMEOUT(drained(), 5000);
        hooks::linux_watch_publication_pause_released.store(true);
        hooks::linux_watch_publication_pause_released.notify_all();
        maintenance.join();
        if (remove_shared_directory) {
            QVERIFY(!armed);
            QVERIFY(!backend.identity_matches(1));
            QVERIFY(!backend.identity_matches(3));
            QCOMPARE(backend.allocated_registrations(), size_t(1));
            return;
        }
        QVERIFY2(armed, qPrintable(error));
        QVERIFY(backend.identity_matches(1));
        QVERIFY(backend.identity_matches(3));
        QCOMPARE(backend.allocated_registrations(), size_t(2));
        const auto after = QStringLiteral("after-admission.txt");
        QVERIFY(write_file(QDir(original).filePath(after)));
        QSet<uint64_t> observed;
        const auto delivered_to_both = [&] {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                const auto path = QDir(change.registration == 1 ? original : alias).filePath(after);
                for (const auto& event : change.batch.events) {
                    if (event.path == path) {
                        observed.insert(change.registration);
                    }
                }
            }
            return observed == QSet<uint64_t>{1, 3};
        };
        QTRY_VERIFY_WITH_TIMEOUT(delivered_to_both(), 5000);
    }

    void native_detail_drained_before_watch_publication_requires_reconciliation()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir first;
        QTemporaryDir second;
        QVERIFY(first.isValid() && second.isValid());
        detail::Direct_native_drain drain;
        QString error;
        QVERIFY2(drain.arm(1, first.path(), error), qPrintable(error));
        std::thread maintenance;
        const auto cleanup = qScopeGuard([&] {
            hooks::linux_watch_publication_pause_released.store(true);
            hooks::linux_watch_publication_pause_released.notify_all();
            if (maintenance.joinable()) {
                maintenance.join();
            }
            hooks::linux_pause_watch_publication_requested.store(false);
        });
        hooks::linux_watch_publication_pause_reached.store(false);
        hooks::linux_watch_publication_pause_released.store(false);
        hooks::linux_pause_watch_publication_requested.store(true);
        bool armed = false;
        maintenance = std::thread([&] { armed = drain.arm(2, second.path(), error); });
        QTRY_VERIFY_WITH_TIMEOUT(hooks::linux_watch_publication_pause_reached.load(), 5000);
        const auto before = drain.resource_counts().batches;
        QVERIFY(write_file(second.filePath(QStringLiteral("before-publication.txt"))));
        QVERIFY(write_file(first.filePath(QStringLiteral("drain-marker.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().batches > before, 5000);
        hooks::linux_watch_publication_pause_released.store(true);
        hooks::linux_watch_publication_pause_released.notify_all();
        maintenance.join();
        QVERIFY2(armed, qPrintable(error));
        QList<detail::Direct_change> changes;
        const auto received_admission = [&] {
            changes.append(drain.wait(std::chrono::milliseconds(10)).changes);
            return std::any_of(changes.cbegin(), changes.cend(), [](const auto& change) {
                return change.registration == 2;
            });
        };
        QTRY_VERIFY_WITH_TIMEOUT(received_admission(), 5000);
        const auto found = std::find_if(changes.cbegin(), changes.cend(), [](const auto& change) {
            return change.registration == 2;
        });
        QVERIFY(found != changes.cend());
        QVERIFY(found->batch.rescan_required);
        QVERIFY(!found->batch.rescan_event_paths_complete);
        QVERIFY(!found->coverage_lost);
    }
#endif

    void native_identity_loss_discards_configured_path_detail_data()
    {
        QTest::addColumn<bool>("move_ancestor");
        QTest::newRow("watched-directory-moved") << false;
#ifdef Q_OS_LINUX
        // A Windows raw child handle prevents this move; its registry instead
        // shares a recursive ancestor anchor, covered by the scheduler tests.
        QTest::newRow("ancestor-moved") << true;
#endif
    }

    void native_identity_loss_discards_configured_path_detail()
    {
        // Oracle: after its directory or ancestor moves, a source still owes
        // reconciliation but cannot attribute the moved tree's edits to its old path.
        QFETCH(bool, move_ancestor);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto ancestor = workspace.filePath(QStringLiteral("ancestor"));
        const auto watched  = QDir(ancestor).filePath(QStringLiteral("watched"));
        const auto moved    = workspace.filePath(QStringLiteral("moved"));
        QVERIFY(QDir().mkpath(watched));
        detail::Direct_native_drain drain;
        QString error;
        QVERIFY2(drain.arm(1, watched, error), qPrintable(error));
        QVERIFY(write_file(QDir(watched).filePath(QStringLiteral("before-move.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().detail_bytes > 0, 5000);
        QVERIFY(QDir().rename(move_ancestor ? ancestor : watched, moved));
        const auto moved_watch = move_ancestor ? QDir(moved).filePath(QStringLiteral("watched")) : moved;
        QVERIFY(write_file(QDir(moved_watch).filePath(QStringLiteral("retired-tree.txt"))));
        QVERIFY(!drain.identity_matches(1));
        const auto changes = drain.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(changes.size(), 1);
        QCOMPARE(changes[0].registration, uint64_t(1));
        QVERIFY(changes[0].coverage_lost);
        QVERIFY(changes[0].batch.rescan_required);
        QVERIFY(!changes[0].batch.rescan_event_paths_complete);
        QVERIFY(changes[0].batch.events.isEmpty());
        drain.retire(1);
    }

    void native_drain_continues_while_registry_delivery_is_held()
    {
        // Oracle: native observation must remain independent of registry and
        // receiver latency, while the receiver still receives subsequent edits.
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString first = directory.filePath(QStringLiteral("first.txt"));
        const QString second = directory.filePath(QStringLiteral("second.txt"));
        Native_capture capture;
        QSemaphore entered;
        QSemaphore release;
        std::atomic_bool hold = true;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) {
            capture.receive(batch);
            if (std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                    return event.path == first;
                }) && hold.exchange(false))
            {
                entered.release();
                release.acquire();
            }
        });
        const auto cleanup = qScopeGuard([&] {
            release.release();
            registry.detach(client);
        });
        registry.replace(client, {{directory.path(), 0}}, Watch_mode::DIRECT,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(write_file(first));
        QVERIFY(entered.tryAcquire(1, 5000));
        const auto native_before = detail::native_test_hooks::native_notifications.load();
        QVERIFY(write_file(second));
        QTRY_VERIFY_WITH_TIMEOUT(detail::native_test_hooks::native_notifications.load() > native_before, 5000);
        release.release();
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                    return event.path == second;
                });
            });
        }));
    }

    void native_handoff_overflow_is_bounded_and_requires_reconciliation()
    {
        // Oracle: bounded handoff loss is explicit; an armed source cannot
        // silently turn missing events into a complete path-scoped capture.
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        constexpr size_t k_detail_budget = 1024;
        detail::Direct_native_drain drain(k_detail_budget);
        QString error;
        QVERIFY2(drain.arm(1, directory.path(), error), qPrintable(error));
        for (int index = 0; index != 32; ++index) {
            QVERIFY(write_file(directory.filePath(QStringLiteral("changed-%1.txt").arg(index))));
        }
        QTRY_VERIFY_WITH_TIMEOUT(drain.resource_counts().handoff_overflows > 0, 5000);
        QCOMPARE(drain.resource_counts().kernel_overflows, uint64_t(0));
        QCOMPARE(drain.resource_counts().decoder_budget_losses, uint64_t(0));
        QVERIFY(drain.resource_counts().detail_bytes <= k_detail_budget);
        QVERIFY(drain.resource_counts().peak_detail_bytes <= k_detail_budget);
        const auto changes = drain.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(changes.size(), 1);
        QVERIFY(changes[0].batch.rescan_required);
        QVERIFY(!changes[0].batch.rescan_event_paths_complete);
        QVERIFY(!changes[0].batch.consumer_reconciliation_only);
        QCOMPARE(changes[0].batch.reason, Native_reason::QUEUE_OVERFLOW);
        QVERIFY(!changes[0].coverage_lost);
        QVERIFY(drain.identity_matches(1));
        // Drain already-completed notifications before checking that ordinary
        // detail resumes after the consumer has accepted the loss obligation.
        while (!drain.wait(std::chrono::milliseconds(100)).changes.isEmpty()) {}
        const auto after = directory.filePath(QStringLiteral("after.txt"));
        QVERIFY(write_file(after));
        bool observed = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!observed && std::chrono::steady_clock::now() < deadline) {
            for (const auto& change : drain.wait(std::chrono::milliseconds(100)).changes) {
                for (const auto& event : change.batch.events) {
                    observed |= event.path == after;
                }
            }
        }
        QVERIFY(observed);
    }

#ifdef Q_OS_MACOS
    void macos_native_detail_keeps_scope_types_and_unpaired_renames()
    {
        // Apple's file events name endpoints without a rename cookie or orientation.
        const QString root = QStringLiteral("/tmp/observation");
        const QString native_root = QStringLiteral("/private/tmp/observation");
        const char* paths[] = {
            "/private/tmp/observation/note.txt",
            "/private/tmp/observation/child",
            "/private/tmp/observation/child/deep.txt",
            "/private/tmp/observation/before.txt",
            "/private/tmp/observation/after.txt",
        };
        const uint32_t flags[] = {
            kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemIsFile,
            kFSEventStreamEventFlagItemCreated  | kFSEventStreamEventFlagItemIsDir,
            kFSEventStreamEventFlagItemCreated  | kFSEventStreamEventFlagItemIsFile,
            kFSEventStreamEventFlagItemRenamed  | kFSEventStreamEventFlagItemIsFile,
            kFSEventStreamEventFlagItemRenamed  | kFSEventStreamEventFlagItemIsFile,
        };
        const uint64_t ids[] = {101, 102, 103, 104, 105};
        const auto batch = detail::decode_macos_notifications(root, native_root, 5,
            paths, flags, ids, 100).batch;
        QCOMPARE(batch.root, root);
        QCOMPARE(batch.events.size(), 4);
        QCOMPARE(batch.events[0].path, root + QStringLiteral("/note.txt"));
        QCOMPARE(batch.events[0].kind, Event_kind::MODIFIED);
        QCOMPARE(batch.events[0].entry_type, Entry_type::NON_DIRECTORY);
        QCOMPARE(batch.events[1].entry_type, Entry_type::DIRECTORY);
        QCOMPARE(batch.events[2].kind, Event_kind::RENAMED);
        QCOMPARE(batch.events[3].kind, Event_kind::RENAMED);
        QVERIFY(batch.events[2].old_path.isEmpty());
        QVERIFY(batch.events[3].old_path.isEmpty());
        QVERIFY(batch.rescan_required);
        QVERIFY(batch.rescan_event_paths_complete);

        const char* lost_paths[] = {"/private/tmp/observation", "/private/tmp/observation"};
        const uint32_t lost_flags[] = {
            kFSEventStreamEventFlagRootChanged,
            kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagMustScanSubDirs,
        };
        const uint64_t lost_ids[] = {0, 1};
        const auto lost = detail::decode_macos_notifications(root, native_root, 2,
            lost_paths, lost_flags, lost_ids, 100).batch;
        QVERIFY(lost.rescan_required);
        QVERIFY(!lost.rescan_event_paths_complete);
        QCOMPARE(lost.reason, Native_reason::COVERAGE_CHANGED);

        for (const uint32_t dropped : {kFSEventStreamEventFlagUserDropped, kFSEventStreamEventFlagKernelDropped}) {
            const uint32_t dropped_flags[] = {dropped | kFSEventStreamEventFlagMustScanSubDirs};
            const auto overflow = detail::decode_macos_notifications(root, native_root, 1,
                lost_paths + 1, dropped_flags, lost_ids + 1, 100).batch;
            QCOMPARE(overflow.reason, Native_reason::QUEUE_OVERFLOW);
            QVERIFY(overflow.rescan_required);
            QVERIFY(!overflow.rescan_event_paths_complete);
        }

        const uint32_t replaced_flags[] = {
            kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemRemoved |
                kFSEventStreamEventFlagItemIsFile,
        };
        const auto replaced = detail::decode_macos_notifications(root, native_root, 1,
            paths, replaced_flags, ids, 100).batch;
        QVERIFY(replaced.rescan_required);
        QVERIFY(replaced.rescan_event_paths_complete);
        QCOMPARE(replaced.events.front().path, root + QStringLiteral("/note.txt"));

        // Initial readback covers events at or before the native sequence cutoff,
        // even when FSEvents repeats their IDs after the arm flush returns.
        const auto after_baseline = detail::decode_macos_notifications(root, native_root, 2,
            paths, flags, ids, 101).batch;
        QCOMPARE(after_baseline.events.size(), 1);
        QCOMPARE(after_baseline.events.front().path, root + QStringLiteral("/child"));
        const auto before_baseline = detail::decode_macos_notifications(root, native_root, 2,
            paths, flags, ids, 102).batch;
        QVERIFY(before_baseline.root.isEmpty());

        const uint32_t wrapped_flags[] = {
            kFSEventStreamEventFlagEventIdsWrapped,
            kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemIsDir,
        };
        const auto wrapped = detail::decode_macos_notifications(root, native_root, 2,
            paths, wrapped_flags, lost_ids, 100).batch;
        QVERIFY(wrapped.rescan_required);
        QVERIFY(!wrapped.rescan_event_paths_complete);
        QCOMPARE(wrapped.events.size(), 1);
        QCOMPARE(wrapped.events.front().path, root + QStringLiteral("/child"));
    }

    void macos_native_decoder_reports_budget_loss()
    {
        // Resource counters distinguish native decoder truncation from the later
        // drain handoff limit; truncated detail always owes full reconciliation.
        const QString root = QStringLiteral("/private/tmp/observation");
        std::vector<QByteArray>  names;
        std::vector<const char*> paths;
        std::vector<uint32_t>    flags;
        std::vector<uint64_t>    ids;
        for (int index = 0; index != 300; ++index) {
            names.push_back(QStringLiteral("/private/tmp/observation/file-%1.txt").arg(index).toUtf8());
            flags.push_back(kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemIsFile);
            ids.push_back(101 + uint64_t(index));
        }
        for (const auto& name : names) {
            paths.push_back(name.constData());
        }
        const auto decoded = detail::decode_macos_notifications(root, root,
            paths.size(), paths.data(), flags.data(), ids.data(), 100);
        QVERIFY(decoded.budget_exceeded);
        QVERIFY(decoded.batch.rescan_required);
        QVERIFY(!decoded.batch.rescan_event_paths_complete);
        QCOMPARE(decoded.batch.reason, Native_reason::DETAIL_UNAVAILABLE);
        QVERIFY(decoded.batch.events.size() < qsizetype(paths.size()));
    }

    void macos_native_backend_observes_content_and_retires_context()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString root = workspace.filePath(QStringLiteral("root"));
        const QString file = root + QStringLiteral("/note.txt");
        QVERIFY(QDir().mkpath(root + QStringLiteral("/child")));
        QVERIFY(write_file(file));
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, root, error), qPrintable(error));
        QVERIFY(backend.identity_matches(1));
        QVERIFY(write_file(file, QByteArray("modified after native arming\n")));
        bool content_observed = false;
        QElapsedTimer deadline;
        deadline.start();
        while (!content_observed && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(200)).changes) {
                for (const auto& event : change.batch.events) {
                    content_observed |= event.path == file;
                }
            }
        }
        QVERIFY(content_observed);
        QCOMPARE(backend.allocated_registrations(), size_t(1));

        QVERIFY(QDir(workspace.path()).rename(QStringLiteral("root"), QStringLiteral("moved")));
        QVERIFY(QDir().mkpath(root));
        QVERIFY(!backend.identity_matches(1));
        bool coverage_lost = false;
        deadline.restart();
        while (!coverage_lost && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(200)).changes) {
                coverage_lost |= change.registration == 1 && change.coverage_lost;
            }
        }
        QVERIFY(coverage_lost);
        backend.retire(1);
        QCOMPARE(backend.allocated_registrations(), size_t(0));
        QCOMPARE(backend.allocated_bytes(), size_t(0));

        // RootChanged has no ordered event ID. A later marker on the stable
        // ancestor puts the rename traffic before the replacement stream starts.
        {
            detail::Direct_native_backend witness;
            QVERIFY2(witness.arm(1, workspace.path(), error), qPrintable(error));
            const QString marker = workspace.filePath(QStringLiteral("replacement-ready"));
            QVERIFY(write_file(marker));
            bool replacement_ready = false;
            deadline.restart();
            while (!replacement_ready && deadline.elapsed() < 5000) {
                for (const auto& change : witness.wait(std::chrono::milliseconds(200)).changes) {
                    for (const auto& event : change.batch.events) {
                        replacement_ready |= event.path == marker;
                    }
                }
            }
            QVERIFY(replacement_ready);
        }
        QVERIFY2(backend.arm(2, root, error), qPrintable(error));
        QVERIFY(backend.identity_matches(2));
        backend.retire(2);
        QVERIFY(backend.wait(std::chrono::milliseconds(50)).changes.isEmpty());

        // Wake can precede waiting and must remain effective without native streams.
        backend.wake();
        deadline.restart();
        QVERIFY(backend.wait(std::chrono::seconds(3)).changes.isEmpty());
        QVERIFY(deadline.elapsed() < 1000);
    }

    void macos_shared_ancestor_detail_invalidates_changed_paths()
    {
        const QString root = QStringLiteral("/logical/child");
        const QString native_root = QStringLiteral("/physical/parent/child");
        const uint64_t ids[] = {101};
        for (const char* path : {"/physical/parent/child", "/physical/parent"}) {
            for (const uint32_t flag : {
                     kFSEventStreamEventFlagItemRenamed, kFSEventStreamEventFlagItemRemoved})
            {
                const uint32_t flags[] = {flag | kFSEventStreamEventFlagItemIsDir};
                const auto batch = detail::decode_macos_notifications(root, native_root, 1,
                    &path, flags, ids, 100).batch;
                QCOMPARE(batch.root, root);
                QCOMPARE(batch.reason, Native_reason::COVERAGE_CHANGED);
                QVERIFY(batch.rescan_required);
                QVERIFY(!batch.rescan_event_paths_complete);
                QVERIFY(batch.events.isEmpty());
            }
        }
        const char* sibling = "/physical/parent-other";
        const uint32_t renamed[] = {kFSEventStreamEventFlagItemRenamed | kFSEventStreamEventFlagItemIsDir};
        QVERIFY(detail::decode_macos_notifications(root, native_root, 1,
            &sibling, renamed, ids, 100).batch.root.isEmpty());
        const char* ancestor = "/physical/parent";
        const uint32_t incomplete[] = {kFSEventStreamEventFlagMustScanSubDirs};
        const auto rescan = detail::decode_macos_notifications(root, native_root, 1,
            &ancestor, incomplete, ids, 100).batch;
        QCOMPARE(rescan.root, root);
        QVERIFY(rescan.rescan_required);
        QVERIFY(!rescan.rescan_event_paths_complete);
        QVERIFY(detail::decode_macos_notifications(root, native_root, 1,
            &sibling, incomplete, ids, 100).batch.root.isEmpty());
    }

    void macos_ancestor_promotion_delivers_buffered_descendant_events()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString ancestor = workspace.filePath(QStringLiteral("root"));
        const QString descendant = ancestor + QStringLiteral("/child");
        const QString file = descendant + QStringLiteral("/buffered.txt");
        QVERIFY(QDir().mkpath(descendant));
        QString error;
        detail::Direct_native_backend witness;
        QVERIFY2(witness.arm(1, descendant, error), qPrintable(error));

        detail::Direct_native_backend backend;
        detail::native_test_hooks::macos_defer_delivery.store(true);
        const auto restore_delivery = qScopeGuard([] {
            detail::native_test_hooks::macos_defer_delivery.store(false);
        });
        QVERIFY2(backend.arm(1, descendant, error), qPrintable(error));
        detail::native_test_hooks::macos_defer_delivery.store(false);
        QVERIFY(write_file(file));

        // The independent stream proves the mutation has a native event ID before
        // promotion starts. The original stream must still hold its delayed detail.
        bool witnessed = false;
        QElapsedTimer deadline;
        deadline.start();
        while (!witnessed && deadline.elapsed() < 5000) {
            for (const auto& change : witness.wait(std::chrono::milliseconds(200)).changes) {
                for (const auto& event : change.batch.events) {
                    witnessed |= event.path == file;
                }
            }
        }
        QVERIFY(witnessed);
        QVERIFY(backend.wait(std::chrono::milliseconds(0)).changes.isEmpty());
        QVERIFY2(backend.arm(2, ancestor, error), qPrintable(error));

        bool delivered = false;
        deadline.restart();
        while (!delivered && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(200)).changes) {
                QVERIFY(!change.coverage_lost);
                for (const auto& event : change.batch.events) {
                    delivered |= change.registration == 1 && event.path == file;
                }
            }
        }
        QVERIFY(delivered);
    }

    void macos_shared_ancestor_keeps_descendants_and_releases_descriptors_data()
    {
        QTest::addColumn<bool>("descendant_first");
        QTest::newRow("ancestor-first")   << false;
        QTest::newRow("descendant-first") << true;
    }

    void macos_shared_ancestor_keeps_descendants_and_releases_descriptors()
    {
        QFETCH(bool, descendant_first);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString parent = workspace.filePath(QStringLiteral("projects/checkout/.git"));
        const QString anchor = parent + QStringLiteral("/refs");
        QStringList children;
        for (int index = 0; index != 8; ++index) {
            children.append(anchor + QStringLiteral("/branch-%1/nested").arg(index));
            QVERIFY(QDir().mkpath(children.back()));
        }
        const long descriptor_limit = sysconf(_SC_OPEN_MAX);
        QVERIFY(descriptor_limit > 0);
        const auto descriptor_count = [descriptor_limit] {
            int count = 0;
            for (long descriptor = 0; descriptor < descriptor_limit; ++descriptor) {
                count += fcntl(int(descriptor), F_GETFD) != -1;
            }
            return count;
        };
        const int original_descriptors = descriptor_count();
        detail::Direct_native_backend backend;
        QString error;
        int ancestor_descriptors = 0;
        if (descendant_first) {
            QVERIFY2(backend.arm(1, children.front(), error), qPrintable(error));
            ancestor_descriptors = descriptor_count();
        }
        QVERIFY2(backend.arm(100, anchor, error), qPrintable(error));
        if (!descendant_first) {
            ancestor_descriptors = descriptor_count();
        }
        for (int index = descendant_first ? 1 : 0; index != children.size(); ++index) {
            QVERIFY2(backend.arm(uint64_t(index + 1), children[index], error), qPrintable(error));
        }
        // These logical descendants already have native coverage. They must not
        // each retain another full chain of WatchRoot ancestor descriptors.
        QTRY_VERIFY_WITH_TIMEOUT(descriptor_count() <= ancestor_descriptors, 5000);
        QCOMPARE(backend.allocated_registrations(), size_t(9));
        backend.retire(100);
        QCOMPARE(backend.allocated_registrations(), size_t(8));
        for (const auto& child : children) {
            QVERIFY(write_file(child + QStringLiteral("/note.txt")));
        }
        QVERIFY(write_file(anchor + QStringLiteral("/outside.txt")));
        unsigned content = 0;
        QElapsedTimer deadline;
        deadline.start();
        while (content != 255 && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                QVERIFY(change.registration >= 1 && change.registration <= 8);
                QVERIFY(!change.coverage_lost);
                const QString expected = children[int(change.registration - 1)] + QStringLiteral("/note.txt");
                for (const auto& event : change.batch.events) {
                    QVERIFY(event.path != anchor + QStringLiteral("/outside.txt"));
                    if (event.path == expected) {
                        content |= 1u << (change.registration - 1);
                    }
                }
            }
        }
        QCOMPARE(content, 255u);

        backend.retire(1);
        QVERIFY(write_file(children[0] + QStringLiteral("/retired.txt")));
        QVERIFY(write_file(children[1] + QStringLiteral("/surviving.txt")));
        bool survivor_observed = false;
        deadline.restart();
        while (!survivor_observed && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                QVERIFY(change.registration != 1 && change.registration != 100);
                for (const auto& event : change.batch.events) {
                    survivor_observed |= change.registration == 2 &&
                        event.path == children[1] + QStringLiteral("/surviving.txt");
                }
            }
        }
        QVERIFY(survivor_observed);

        // An intermediate ancestor can move away and back before readback.
        // Its file event must still invalidate the affected logical directory.
        const QString intermediate = QFileInfo(children[1]).path();
        QVERIFY(QDir().rename(intermediate, intermediate + QStringLiteral("-moved")));
        QVERIFY(QDir().rename(intermediate + QStringLiteral("-moved"), intermediate));
        QVERIFY(backend.identity_matches(2));
        bool child_loss = false;
        deadline.restart();
        while (!child_loss && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                if (change.coverage_lost) {
                    QCOMPARE(change.registration, uint64_t(2));
                    child_loss = true;
                }
            }
        }
        QVERIFY(child_loss);

        QVERIFY(QDir().rename(parent, parent + QStringLiteral("-moved")));
        unsigned lost = 0;
        deadline.restart();
        while (lost != 254 && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                QVERIFY(change.registration >= 2 && change.registration <= 8);
                if (change.coverage_lost) {
                    lost |= 1u << (change.registration - 1);
                }
            }
        }
        QCOMPARE(lost, 254u);
        for (uint64_t id = 2; id <= 8; ++id) {
            backend.retire(id);
        }
        QVERIFY(QDir().rename(parent + QStringLiteral("-moved"), parent));
        QCOMPARE(backend.allocated_registrations(), size_t(0));
        QCOMPARE(backend.allocated_bytes(), size_t(0));
        QVERIFY(backend.wait(std::chrono::milliseconds(50)).changes.isEmpty());
        QTRY_VERIFY_WITH_TIMEOUT(descriptor_count() <= original_descriptors, 5000);
    }

    void macos_native_path_spellings_preserve_detail_data()
    {
        QTest::addColumn<QString>("directory_name");
        QTest::addColumn<QString>("file_name");
        QTest::addColumn<bool>("alternate_case");
        QTest::newRow("mixed-case") << QStringLiteral("MiXeD") << QStringLiteral("NoTe.txt") << false;
        QTest::newRow("alternate-case-root") << QStringLiteral("MiXeD") << QStringLiteral("NoTe.txt") << true;
        QTest::newRow("composed-unicode")
            << QStringLiteral("R\u00e9pertoire") << QStringLiteral("caf\u00e9.txt") << false;
        QTest::newRow("decomposed-unicode")
            << QStringLiteral("Re\u0301pertoire") << QStringLiteral("cafe\u0301.txt") << false;
    }

    void macos_native_path_spellings_preserve_detail()
    {
        QFETCH(QString, directory_name);
        QFETCH(QString, file_name);
        QFETCH(bool, alternate_case);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto created_root = workspace.filePath(directory_name);
        QVERIFY(QDir().mkpath(created_root));
        const auto root = alternate_case ? workspace.filePath(directory_name.toLower()) : created_root;
        if (alternate_case && !QFileInfo(root).isDir()) {
            QSKIP("The native volume distinguishes the alternative case spelling");
        }
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, root, error), qPrintable(error));
        QVERIFY(backend.identity_matches(1));
        QVERIFY(write_file(root + QLatin1Char('/') + file_name));
        // Qt decodes native macOS names as NFC. The configured root spelling
        // remains the logical scope even when its physical spelling differs.
        const auto expected = root + QLatin1Char('/') + file_name.normalized(QString::NormalizationForm_C);
        bool observed = false;
        QElapsedTimer deadline;
        deadline.start();
        while (!observed && deadline.elapsed() < 5000) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(200)).changes) {
                QVERIFY(!change.coverage_lost);
                for (const auto& event : change.batch.events) {
                    if (event.path == expected) {
                        QCOMPARE(change.batch.root, root);
                        QCOMPARE(change.batch.scope, root);
                        QCOMPARE(event.entry_type, Entry_type::NON_DIRECTORY);
                        observed = true;
                    }
                }
            }
        }
        QVERIFY2(observed, qPrintable(expected));
        backend.retire(1);
        QCOMPARE(backend.allocated_registrations(), size_t(0));
    }

    void macos_registry_overflow_reconciles_retained_registrations()
    {
        // The decoder separately maps dropped flags to QUEUE_OVERFLOW. Inject
        // that native reason at the existing registry seam to verify readback.
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        QVERIFY(QDir().mkpath(root + QStringLiteral("/nested")));
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        auto release = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        // Admission completes an attempt; native setup may still require a
        // recursive scan before this fixture has healthy coverage.
        QTRY_VERIFY2_WITH_TIMEOUT(registry.covers(client, root),
            qPrintable(registry.coverage_status(client, root).diagnostic), 5000);
        const auto revision = registry.revision(client, root);
        const auto armed = registry.resource_counts().armed;
        const auto expansions = registry.expansion_count_for_tests(client);
        registry.inject_overflow_for_tests(client);
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return batch.root == root && batch.reason == Native_reason::QUEUE_OVERFLOW &&
                    batch.rescan_required && !batch.rescan_event_paths_complete;
            });
        }));
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root) &&
            registry.expansion_count_for_tests(client) > expansions, 5000);
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return batch.root == root && batch.coverage_revision > revision &&
                    batch.events.isEmpty() && batch.rescan_required;
            });
        }));
        QCOMPARE(registry.resource_counts().armed, armed);
        registry.detach(client);
        release.dismiss();
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().native_bytes, size_t(0), 5000);
    }

    void macos_retargeted_alias_discards_obsolete_native_detail()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString first  = workspace.filePath(QStringLiteral("first"));
        const QString second = workspace.filePath(QStringLiteral("second"));
        const QString alias  = workspace.filePath(QStringLiteral("alias"));
        QVERIFY(QDir().mkpath(first));
        QVERIFY(QDir().mkpath(second));
        QVERIFY(QFile::link(first, alias));
        detail::Direct_native_drain drain;
        QString error;
        QVERIFY2(drain.arm(1, alias, error), qPrintable(error));
        QVERIFY(QFile::remove(alias));
        QVERIFY(QFile::link(second, alias));
        QVERIFY(write_file(first + QStringLiteral("/obsolete.txt")));
        bool loss_observed = false;
        QElapsedTimer deadline;
        deadline.start();
        while (!loss_observed && deadline.elapsed() < 5000) {
            for (const auto& change : drain.wait(std::chrono::milliseconds(200)).changes) {
                QVERIFY(change.coverage_lost);
                QVERIFY(change.batch.rescan_required);
                QVERIFY(!change.batch.rescan_event_paths_complete);
                QVERIFY(change.batch.events.isEmpty());
                loss_observed = true;
            }
        }
        QVERIFY(loss_observed);
        drain.retire(1);

        // An alias can follow its original directory to a new spelling while the
        // canonical path watched by FSEvents is replaced with a different inode.
        QVERIFY2(drain.arm(2, alias, error), qPrintable(error));
        const QString moved = workspace.filePath(QStringLiteral("moved"));
        QVERIFY(QDir().rename(second, moved));
        QVERIFY(QFile::remove(alias));
        QVERIFY(QFile::link(moved, alias));
        QVERIFY(QDir().mkpath(second));
        QVERIFY(!drain.identity_matches(2));
        drain.retire(2);
    }
#endif

    void healthy_first_admission_does_not_rescan_unchanged_coverage()
    {
#ifndef Q_OS_WIN
        QSKIP("This regression exercises Windows first-identity admission");
#else
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        constexpr int descendants = 64;
        for (int index = 0; index != descendants; ++index) {
            QVERIFY(QDir(workspace.path()).mkdir(QStringLiteral("child-%1").arg(index)));
        }
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto cleanup = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, {{workspace.path(), 1}}, Watch_mode::DISCOVERY_RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, workspace.path()), 5000);
        const auto work = registry.maintenance_counts_for_tests(client);
        QVERIFY(work.identity_candidates >= descendants);
        qInfo("first-admission descendants=%d identity_candidates=%llu read_summary_nodes=%llu",
            descendants, static_cast<unsigned long long>(work.identity_candidates),
            static_cast<unsigned long long>(work.read_summary_nodes));
        QVERIFY2(work.read_summary_nodes <= 4 * descendants,
            "Unchanged pending first identities repeatedly traverse the populated root summary");
#endif
    }

    void recursive_incompleteness_is_published_before_continuation_data()
    {
        QTest::addColumn<bool>("pending_filter");
        QTest::newRow("new-unarmed-child") << false;
        QTest::newRow("pending-eligibility") << true;
    }

    void recursive_incompleteness_is_published_before_continuation()
    {
        QFETCH(bool, pending_filter);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString root = workspace.path();
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        std::atomic_bool filter_pending = false;
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(),
            [&](const QString&, const QString&) {
                if (filter_pending.load()) {
                    throw Directory_filter_pending();
                }
                return true;
            }, true);
        QVERIFY(registry.covers(client, root));
        QSemaphore paused;
        QSemaphore resume;
        std::atomic_bool pause_once = true;
        std::atomic_bool park_timed_out = false;
        registry.set_maintenance_observer_for_tests([&](detail::Direct_registry::Maintenance_stage stage) {
            if (stage == detail::Direct_registry::Maintenance_stage::SCAN_APPLIED && pause_once.exchange(false)) {
                paused.release();
                if (!resume.tryAcquire(1, 5000)) {
                    park_timed_out.store(true);
                }
            }
        });
        const auto cleanup = qScopeGuard([&] {
            resume.release();
            registry.set_maintenance_observer_for_tests({});
            registry.detach(client);
        });
        filter_pending.store(pending_filter);
        QVERIFY(QDir(root).mkdir(QStringLiteral("new-child")));
        QVERIFY(paused.tryAcquire(1, 5000));
        QCOMPARE(registry.coverage_status(client, root).state, Coverage_state::PENDING);
        QVERIFY(!registry.covers(client, root));
        filter_pending.store(false);
        resume.release();
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        QVERIFY(!park_timed_out.load());
    }

    void coverage_publication_precedes_loss_recovery_and_detach()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString root = workspace.path();
        Native_capture capture;
        detail::Direct_registry registry;
        uint64_t client = 0;
        std::atomic_bool inconsistent_delivery = false;
        client = registry.attach([&](const Native_batch& batch) {
            const auto status = registry.coverage_status(client, root);
            const auto revision = registry.revision(client, root);
            if (revision < batch.coverage_revision ||
                (batch.reason == Native_reason::REGISTRATION_FAILED &&
                    status.state != Coverage_state::FAILED))
            {
                inconsistent_delivery.store(true);
            }
            capture.receive(batch);
        });
        bool attached = true;
        const auto cleanup = qScopeGuard([&] {
            if (attached) {
                registry.detach(client);
            }
        });
        registry.replace(client, {{root, 0}}, Watch_mode::DIRECT,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        const auto initial_revision = registry.revision(client, root);
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return batch.coverage_revision == initial_revision && batch.initial_admission_only &&
                    batch.rescan_required && batch.events.isEmpty();
            });
        }));
        registry.invalidate_content_for_tests(client);
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            uint64_t lost_revision = 0;
            for (const auto& batch : batches) {
                if (batch.coverage_revision <= initial_revision) {
                    continue;
                }
                if (batch.initial_admission_only) {
                    return false;
                }
                if (batch.reason == Native_reason::REGISTRATION_FAILED) {
                    lost_revision = batch.coverage_revision;
                }
                else
                if (lost_revision != 0 && batch.reason == Native_reason::COVERAGE_CHANGED &&
                    batch.coverage_revision > lost_revision)
                {
                    return true;
                }
            }
            return false;
        }));
        QVERIFY(!inconsistent_delivery.load());
        QVERIFY(registry.revision(client, root) > initial_revision);

        std::atomic_bool stop_reader = false;
        std::thread reader([&] {
            while (!stop_reader.load()) {
                (void)registry.coverage_status(client, root);
                (void)registry.revision(client, root);
                std::this_thread::yield();
            }
        });
        registry.detach(client);
        attached = false;
        stop_reader.store(true);
        reader.join();
        QCOMPARE(registry.coverage_status(client, root).state, Coverage_state::FAILED);
        QCOMPARE(registry.revision(client, root), uint64_t(0));
        QVERIFY(!registry.covers(client, root));
        const auto delivered = capture.count();
        QVERIFY(write_file(QDir(root).filePath(QStringLiteral("after-detach.txt"))));
        QTest::qWait(150);
        QCOMPARE(capture.count(), delivered);
    }

    void coverage_reads_preserve_first_captured_match_data()
    {
        QTest::addColumn<bool>("insensitive_first");
        QTest::newRow("insensitive-first") << true;
        QTest::newRow("sensitive-first") << false;
    }

    void coverage_reads_preserve_first_captured_match()
    {
        namespace paths = vnm::path_name;
        QFETCH(bool, insensitive_first);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto insensitive = workspace.filePath(QStringLiteral("Upper/Leaf"));
        const auto sensitive = workspace.filePath(QStringLiteral("upper/Leaf"));
        const auto sensitive_parent = workspace.filePath(QStringLiteral("upper"));
        QVERIFY(QDir().mkpath(insensitive));
        QVERIFY(QDir().mkpath(sensitive));
        auto policy = std::make_shared<paths::Policy_epoch>([&](const QString& parent) {
            return parent == sensitive_parent ? paths::Directory_case_sensitivity::SENSITIVE
                                              : paths::Directory_case_sensitivity::INSENSITIVE;
        });
        detail::Direct_registry registry;
        const auto client = registry.attach([](const Native_batch&) {});
        const auto cleanup = qScopeGuard([&] { registry.detach(client); });
        const QList<Watch_spec> interests = insensitive_first
            ? QList<Watch_spec>{{insensitive, 0}, {sensitive, 0}, {sensitive, 0}}
            : QList<Watch_spec>{{sensitive, 0}, {sensitive, 0}, {insensitive, 0}};
        registry.replace(client, interests, Watch_mode::DIRECT, policy, {}, true);
        QVERIFY(registry.covers(client, sensitive));
        const auto revision = registry.revision(client, sensitive);
        QVERIFY(revision != 0);
        // This spelling matches only the insensitive captured interest. The
        // exact sensitive spelling matches both; it must retain list precedence.
        registry.set_coverage_for_tests(client,
            workspace.filePath(QStringLiteral("Upper/leaf")), false);
        QCOMPARE(registry.coverage_status(client, sensitive).state,
            insensitive_first ? Coverage_state::FAILED : Coverage_state::COVERED);
        QCOMPARE(registry.covers(client, sensitive), !insensitive_first);
        if (insensitive_first) {
            QVERIFY(registry.revision(client, sensitive) > revision);
        }
        else {
            QCOMPARE(registry.revision(client, sensitive), revision);
        }
    }

    void coverage_reads_do_not_wait_for_registry_maintenance_data()
    {
        using Stage = detail::Direct_registry::Maintenance_stage;
        QTest::addColumn<int>("stage");
        QTest::newRow("event-routing") << int(Stage::INGEST);
        QTest::newRow("reconciliation") << int(Stage::RECONCILE);
        QTest::newRow("known-loss-retirement") << int(Stage::RETIREMENT);
    }

    void coverage_reads_do_not_wait_for_registry_maintenance()
    {
        using Stage = detail::Direct_registry::Maintenance_stage;
        QFETCH(int, stage);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString root = workspace.path();
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        std::atomic_int policy_queries = 0;
        auto policy = std::make_shared<vnm::path_name::Policy_epoch>([&](const QString&) {
            ++policy_queries;
#ifdef Q_OS_WIN
            return vnm::path_name::Directory_case_sensitivity::INSENSITIVE;
#else
            return vnm::path_name::Directory_case_sensitivity::SENSITIVE;
#endif
        });
        registry.replace(client, {{root, 0}}, Watch_mode::DIRECT, policy, {}, true);
        QVERIFY(registry.covers(client, root));
        const auto initial_revision = registry.revision(client, root);
        QVERIFY(initial_revision != 0);

        QSemaphore paused;
        QSemaphore resume;
        QSemaphore read_finished;
        std::atomic_bool pause_once = true;
        std::atomic_bool park_timed_out = false;
        registry.set_maintenance_observer_for_tests([&](Stage observed) {
            if (int(observed) == stage && pause_once.exchange(false)) {
                paused.release();
                if (!resume.tryAcquire(1, 5000)) {
                    park_timed_out.store(true);
                }
            }
        }, client);
        const auto cleanup = qScopeGuard([&] {
            resume.release();
            registry.set_maintenance_observer_for_tests({});
            registry.detach(client);
        });
        QVERIFY(paused.tryAcquire(1, 5000));
        const int queries_before = policy_queries.load();
        Coverage_status status;
        Coverage_status unknown_status;
        uint64_t revision = 0;
        bool covered = false;
        int queries_after = -1;
        std::thread reader([&] {
            covered = registry.covers(client, root);
            status = registry.coverage_status(client, root);
            revision = registry.revision(client, root);
            unknown_status = registry.coverage_status(client,
                root + QStringLiteral("/not-an-interest/child"));
            queries_after = policy_queries.load();
            read_finished.release();
        });
        const bool finished_while_locked = read_finished.tryAcquire(1, 1000);
        resume.release();
        reader.join();
        QVERIFY2(finished_while_locked, "Coverage reads waited for unrelated registry maintenance");
        QVERIFY(!park_timed_out.load());
        QCOMPARE(queries_after, queries_before);
        QCOMPARE(unknown_status.state, Coverage_state::FAILED);
        QVERIFY(revision >= initial_revision);
        if (stage == int(Stage::RETIREMENT)) {
            QCOMPARE(status.state, Coverage_state::FAILED);
            QVERIFY(!covered);
        }
    }

    void partial_rename_scope_never_hides_discarded_detail()
    {
        const QString root = QStringLiteral("/observed");
        Native_batch partial;
        partial.events.append({{}, root + QStringLiteral("/old"), Event_kind::RENAMED});
        partial = detail::complete_native_batch(std::move(partial), root, 0);
        QVERIFY(partial.rescan_required);
        QVERIFY(partial.rescan_event_paths_complete);

        auto overflow = partial;
        detail::mark_native_rescan(overflow, QStringLiteral("overflow"), Native_reason::QUEUE_OVERFLOW);
        overflow = detail::complete_native_batch(std::move(overflow), root, 0);
        QVERIFY(overflow.rescan_required);
        QVERIFY(!overflow.rescan_event_paths_complete);
        QCOMPARE(overflow.reason, Native_reason::QUEUE_OVERFLOW);

        auto bounded = partial;
        for (int index = 0; index < 256; ++index) {
            detail::append_native_event(bounded,
                {root + QStringLiteral("/%1").arg(index), {}, Event_kind::MODIFIED});
        }
        bounded = detail::complete_native_batch(std::move(bounded), root, 0);
        QVERIFY(bounded.rescan_required);
        QVERIFY(!bounded.rescan_event_paths_complete);
        QCOMPARE(bounded.events.size(), 256);

        auto malformed = partial;
        detail::mark_native_rescan(malformed, QStringLiteral("truncated detail"));
        malformed = detail::complete_native_batch(std::move(malformed), root, 0);
        QVERIFY(!malformed.rescan_event_paths_complete);
        Native_batch unnamed;
        unnamed.events.append({{}, {}, Event_kind::RENAMED});
        unnamed = detail::complete_native_batch(std::move(unnamed), root, 0);
        QVERIFY(unnamed.rescan_required);
        QVERIFY(!unnamed.rescan_event_paths_complete);
    }

#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    void recursive_plan_growth_replacement_and_release_data()
    {
        QTest::addColumn<bool>("uncapped");
        QTest::newRow("bounded") << false;
        QTest::newRow("uncapped") << true;
    }

    void recursive_plan_growth_replacement_and_release()
    {
        QFETCH(bool, uncapped);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto large = workspace.filePath(QStringLiteral("large"));
        const auto replacement = workspace.filePath(QStringLiteral("replacement"));
        QVERIFY(QDir().mkpath(replacement));
        for (int index = 0; index != 4000; ++index) {
            QVERIFY(QDir().mkpath(large + QStringLiteral("/directory-%1").arg(index)));
        }
        detail::direct_limits_t limits;
        const size_t bounded_bytes = limits.plan_bytes;
        if (uncapped) {
            limits.bounded_workload = false;
        }
        Native_capture capture;
        detail::Direct_registry registry(limits);
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        auto release = qScopeGuard([&] { registry.detach(client); });
        const auto policy = std::make_shared<vnm::path_name::Policy_epoch>();
        registry.replace(client, {{large, 0}}, Watch_mode::RECURSIVE, policy, {}, true);
        if (uncapped) {
            const auto failure_context = [&] {
                const auto resources = registry.resource_counts();
                return QStringLiteral("%1; logical=%2 covered_logical=%3 armed=%4 "
                    "scan_pending=%5 scan_failed=%6 native_bytes=%7 plan_bytes=%8 "
                    "queued_result_bytes=%9 scan_jobs=%10")
                    .arg(capture.diagnostics())
                    .arg(resources.logical_directories)
                    .arg(resources.covered_logical_directories)
                    .arg(resources.armed)
                    .arg(resources.scan_pending)
                    .arg(resources.scan_failed)
                    .arg(resources.native_bytes)
                    .arg(resources.plan_bytes)
                    .arg(resources.scan_result_bytes)
                    .arg(resources.scan_jobs);
            };
            // replace() reports the first attempt, which may precede complete arming.
            // This fixture's 4000-directory acquisition measured 65 seconds on Windows.
            const bool covered = QTest::qWaitFor([&] { return registry.covers(client, large); }, 90'000);
            QVERIFY2(covered, qPrintable(failure_context()));
            QVERIFY(registry.resource_counts().plan_bytes > bounded_bytes);
        }
        else {
            QVERIFY(!registry.covers(client, large));
            QVERIFY(registry.resource_counts().plan_bytes <= bounded_bytes);
            QVERIFY(capture.wait_for([](const QList<Native_batch>& batches) {
                return std::any_of(batches.cbegin(), batches.cend(), [](const auto& batch) {
                    return batch.diagnostic.contains(QStringLiteral("memory budget exhausted"));
                });
            }));
        }
        registry.replace(client, {{replacement, 0}}, Watch_mode::RECURSIVE, policy, {}, true);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, replacement), 5000);
        QVERIFY(!registry.covers(client, large));
        QTRY_VERIFY_WITH_TIMEOUT(registry.resource_counts().plan_bytes < bounded_bytes, 5000);
        registry.detach(client);
        release.dismiss();
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().plan_bytes, size_t(0), 5000);
    }

#endif

    void plan_allocation_failure_reports_and_recovers()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root/nested"));
        QVERIFY(QDir().mkpath(root));
        detail::direct_limits_t limits;
        limits.bounded_workload = false;
        Native_capture capture;
        detail::Direct_registry registry(limits);
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        auto release = qScopeGuard([&] { registry.detach(client); });
        detail::native_test_hooks::plan_allocation_failure.store(true);
        const auto restore = qScopeGuard([] {
            detail::native_test_hooks::plan_allocation_failure.store(false);
        });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(!registry.covers(client, root));
        QVERIFY(capture.wait_for([](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [](const auto& batch) {
                return batch.diagnostic == QStringLiteral("Directory observation plan allocation failed");
            });
        }));
        QCOMPARE(registry.resource_counts().plan_bytes, size_t(0));
        detail::native_test_hooks::plan_allocation_failure.store(false);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        QVERIFY(registry.resource_counts().plan_bytes != 0);
        registry.detach(client);
        release.dismiss();
        QVERIFY(capture.wait_for([](const QList<Native_batch>& batches) {
            return std::none_of(batches.cbegin(), batches.cend(), [](const auto& batch) {
                return batch.initial_admission_only || batch.consumer_reconciliation_only;
            });
        }));
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().plan_bytes, size_t(0), 5000);
    }

#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    void retained_descendant_source_survives_pending_replacement_data()
    {
        QTest::addColumn<bool>("replace_again");
        QTest::addColumn<bool>("lose_coverage");
        QTest::newRow("detail")              << false << false;
        QTest::newRow("detail-replace")      << true  << false;
        QTest::newRow("detail-loss")         << false << true;
        QTest::newRow("detail-replace-loss") << true  << true;
    }

    void retained_descendant_source_survives_pending_replacement()
    {
        QFETCH(bool, replace_again);
        QFETCH(bool, lose_coverage);
        using namespace std::chrono_literals;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        const auto child = root + QStringLiteral("/child");
        const auto payload = child + QStringLiteral("/payload.txt");
        QVERIFY(QDir().mkpath(child));
        QVERIFY(write_file(payload));
        QSemaphore paused;
        QSemaphore resume;
        std::atomic_bool timed_out = false;
        limits_t limits;
        limits.scan_workers = 2;
        Service service(limits);
        auto channel = std::make_shared<Wait_channel>();
        Subscription_options options;
        options.directories = {{root, 0}};
        options.mode = Watch_mode::RECURSIVE;
        options.interval = 10ms;
        options.directory_filter = [](const QString&, const QString&) { return true; };
        auto subscription = service.subscribe(options, channel);
        auto shared_channel = std::make_shared<Wait_channel>();
        Subscription_options shared_options;
        shared_options.directories = {{child, 0}};
        shared_options.mode = Watch_mode::DIRECT;
        shared_options.interval = 10ms;
        auto shared = service.subscribe(shared_options, shared_channel);
        const auto release = qScopeGuard([&] {
            resume.release(4);
            subscription.reset();
            shared.reset();
        });
        QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root) && shared.covers_directory(child), 5000);
        for (const auto& entry : {std::pair{&subscription, channel}, std::pair{&shared, shared_channel}}) {
            while (auto delivery = entry.second->wait(50ms)) {
                entry.first->acknowledge(delivery->batch.capture);
                delivery->completion.complete();
            }
            QVERIFY(!entry.first->rescan_required());
        }
        const auto held_filter = [&] {
            return [&, once = std::make_shared<std::atomic_bool>(true)](const QString&, const QString& path) {
                if (path == child && once->exchange(false)) {
                    paused.release();
                    if (!resume.tryAcquire(1, 15000)) {
                        timed_out.store(true);
                    }
                }
                return true;
            };
        };
        QVERIFY(subscription.replace_directory_filter(held_filter()));
        QVERIFY(paused.tryAcquire(1, 5000));
        QVERIFY(!subscription.covers_directory(root));
        const auto replan_deadline = std::chrono::steady_clock::now() + 5s;
        auto held = channel->wait(5s);
        // A previously dispatched detail delivery can still own the channel
        // while the requested replan waits. Select its reconciliation without
        // acknowledging either the preceding detail or the pending obligation.
        while (held && !held->batch.rescan_required) {
            held->completion.complete();
            const auto remaining = replan_deadline - std::chrono::steady_clock::now();
            QVERIFY(remaining > 0s);
            held = channel->wait(std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
        }
        QVERIFY(held);
        QString held_diagnostic;
        if (!held->batch.consumer_reconciliation_only) {
            const auto coverage = subscription.coverage_status(root);
            QDebug report(&held_diagnostic);
            report.nospace() << "pre-trigger held batch: valid=" << held->valid()
                << " rescan=" << held->batch.rescan_required
                << " initial=" << held->batch.initial_admission_only
                << " consumer=" << held->batch.consumer_reconciliation_only
                << " all_interests=" << held->batch.all_interests
                << " diagnostic=" << held->batch.diagnostic
                << " scopes=" << held->batch.scopes
                << " capture={subscription=" << held->batch.capture.subscription_id
                << ",generation=" << held->batch.capture.generation
                << ",event=" << held->batch.capture.event_sequence
                << ",coverage=" << held->batch.capture.coverage_sequence << "} events=[";
            for (const auto& event : held->batch.events) {
                report << "{kind=" << int(event.kind) << ",type=" << int(event.entry_type)
                    << ",path=" << event.path << ",old_path=" << event.old_path << "}";
            }
            report << "] current={root=" << root << ",coverage_state=" << int(coverage.state)
                << ",coverage_diagnostic=" << coverage.diagnostic
                << ",coverage_revision=" << subscription.coverage_revision(root)
                << ",covered=" << subscription.covers_directory(root)
                << ",rescan_required=" << subscription.rescan_required() << "}";
        }
        QVERIFY2(held->batch.consumer_reconciliation_only, qPrintable(held_diagnostic));
        QVERIFY(!held->batch.initial_admission_only);

        // The old child interest still sees this edit, but the replacing root
        // has not admitted that child into its new node map yet.
        QVERIFY(write_file(payload, "changed while replacement is pending\n"));
        auto detail = shared_channel->wait(5s);
        QVERIFY(detail);
        QVERIFY(std::any_of(detail->batch.events.cbegin(), detail->batch.events.cend(),
            [&](const Event& event) { return event.path == payload; }));
        shared.acknowledge(detail->batch.capture);
        detail->completion.complete();

        if (replace_again) {
            QVERIFY(subscription.replace_directory_filter(held_filter()));
            QVERIFY(paused.tryAcquire(1, 5000));
            held->completion.complete();
            held = channel->wait(5s);
            QVERIFY(held);
        }
        QVERIFY(subscription.acknowledge(held->batch.capture));
        if (lose_coverage) {
            const auto before_loss = subscription.coverage_revision(root);
            QVERIFY(service.set_directory_available_for_tests(child, false));
            QTRY_VERIFY_WITH_TIMEOUT(subscription.coverage_revision(root) > before_loss, 5000);
            // Losing consumer purity must not stop retained ownership from
            // advancing currentness and rejecting an older accepted capture.
            QVERIFY(!subscription.acknowledge(held->batch.capture));
            QVERIFY(service.set_directory_available_for_tests(child, true));
        }
        resume.release(replace_again ? 2 : 1);
        QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
        held->completion.complete();
        auto reconciled = channel->wait(5s);
        QVERIFY(reconciled);
        QVERIFY(reconciled->batch.rescan_required);
        QVERIFY(!reconciled->batch.initial_admission_only);
        QVERIFY(!reconciled->batch.consumer_reconciliation_only);
        QVERIFY(subscription.acknowledge(reconciled->batch.capture));
        reconciled->completion.complete();
        QVERIFY(!timed_out.load());
    }

    void streamed_child_admission_failure_survives_later_chunks()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        for (int index = 0; index != 32; ++index) {
            QVERIFY(QDir().mkpath(root + QStringLiteral("/child-%1").arg(index)));
        }
        detail::direct_limits_t limits;
        limits.bounded_workload = false;
        Native_capture capture;
        detail::Direct_registry registry(limits);
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        std::atomic_int results = 0;
        std::atomic_bool retry_pending = false;
        std::atomic_bool allow_retry = false;
        std::atomic_bool hook_timed_out = false;
        QString first_candidate;
        auto release = qScopeGuard([&] { registry.detach(client); });
        const auto restore = qScopeGuard([&] {
            detail::native_test_hooks::plan_allocation_failure.store(false);
            allow_retry.store(true);
        });
        registry.set_expansion_observer_for_tests(client, [&](Native_watcher::Expansion_stage stage) {
            if (stage != Native_watcher::Expansion_stage::BEFORE_RESULT) {
                return;
            }
            const int result = ++results;
            if (result == 1) {
                // The root and scan job already exist; refuse the first child chunk.
                detail::native_test_hooks::plan_allocation_failure.store(true);
            }
            else
            if (result == 2) {
                if (!capture.wait_for([](const QList<Native_batch>& batches) {
                    return std::any_of(batches.cbegin(), batches.cend(), [](const auto& batch) {
                        return batch.diagnostic == QStringLiteral("Directory observation plan allocation failed");
                    });
                }))
                {
                    hook_timed_out.store(true);
                }
                detail::native_test_hooks::plan_allocation_failure.store(false);
            }
        });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(),
            [&](const QString&, const QString& path) {
                if (first_candidate.isEmpty()) {
                    first_candidate = path;
                }
                else
                if (path == first_candidate && !allow_retry.load()) {
                    retry_pending.store(true);
                    throw Directory_filter_pending();
                }
                return true;
            }, true);
        QTRY_VERIFY_WITH_TIMEOUT(retry_pending.load(), 5000);
        QVERIFY(results.load() >= 2);
        QVERIFY(!hook_timed_out.load());
        QVERIFY(!registry.covers(client, root));
        const auto status = registry.coverage_status(client, root);
        QCOMPARE(status.state, Coverage_state::FAILED);
        QCOMPARE(status.diagnostic, QStringLiteral("Directory observation plan allocation failed"));
        allow_retry.store(true);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        registry.detach(client);
        release.dismiss();
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().plan_bytes, size_t(0), 5000);
    }

#endif

    void scan_result_allocation_failure_reports_and_recovers()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        QVERIFY(QDir().mkpath(root + QStringLiteral("/nested/leaf")));
        detail::direct_limits_t limits;
        limits.bounded_workload = false;
        Native_capture capture;
        detail::Direct_registry registry(limits);
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        auto release = qScopeGuard([&] { registry.detach(client); });
        detail::native_test_hooks::scan_result_allocation_failure.store(true);
        const auto restore = qScopeGuard([] {
            detail::native_test_hooks::scan_result_allocation_failure.store(false);
        });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(!registry.covers(client, root));
        QVERIFY(capture.wait_for([](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [](const auto& batch) {
                return batch.diagnostic == QStringLiteral("Directory expansion result allocation failed");
            });
        }));
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().scan_jobs, size_t(0), 5000);
        QCOMPARE(registry.resource_counts().scan_result_bytes, size_t(0));
        detail::native_test_hooks::scan_result_allocation_failure.store(false);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        registry.detach(client);
        release.dismiss();
        QVERIFY(capture.wait_for([](const QList<Native_batch>& batches) {
            return std::none_of(batches.cbegin(), batches.cend(), [](const auto& batch) {
                return batch.initial_admission_only || batch.consumer_reconciliation_only;
            });
        }));
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().plan_bytes, size_t(0), 5000);
        QCOMPARE(registry.resource_counts().scan_jobs, size_t(0));
        QCOMPARE(registry.resource_counts().scan_result_bytes, size_t(0));
    }

    void unsubscribe_retires_in_flight_expansion_data()
    {
        QTest::addColumn<bool>("change_policy");
        QTest::newRow("held-result") << false;
        QTest::newRow("rekey-held-result") << true;
    }

    void unsubscribe_retires_in_flight_expansion()
    {
        // A scan accepted before cancellation must not publish after removal,
        // including when its policy generation was replaced while it ran.
        QFETCH(bool, change_policy);
        using Stage = Native_watcher::Expansion_stage;
        namespace path_name = vnm::path_name;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        QVERIFY(QDir().mkpath(workspace.filePath(QStringLiteral("nested"))));
        const int initial_threads = Native_watcher::active_thread_count_for_tests();
        QSemaphore paused;
        QSemaphore resume;
        QSemaphore retiring;
        std::atomic_bool hook_timed_out = false;
        std::atomic_bool removed = false;
        std::atomic_bool pause_once = true;
        std::atomic_int callbacks = 0;
        std::atomic_int stale_callbacks = 0;
        std::atomic_int wrong_paths = 0;
        std::unique_ptr<Native_watcher> watcher;
        watcher = std::make_unique<Native_watcher>([&](const Native_batch& batch) {
            if (removed.load()) {
                ++stale_callbacks;
            }
            if (batch.root != workspace.path()) {
                ++wrong_paths;
            }
            (void)watcher->covers_directory(batch.root);
            ++callbacks;
        }, Watch_mode::RECURSIVE);
        watcher->set_expansion_observer_for_tests([&](Stage stage) {
            if (stage == Stage::WAITING_FOR_RETIREMENT) {
                retiring.release();
            }
            if (stage == Stage::BEFORE_RESULT && pause_once.exchange(false)) {
                paused.release();
                if (!resume.tryAcquire(1, 10000)) {
                    hook_timed_out.store(true);
                }
            }
        });
        std::thread registration([&] { watcher->set_directories({workspace.path()}); });
        std::thread removal;
        const auto finish_workers = qScopeGuard([&] {
            resume.release();
            if (registration.joinable()) {
                registration.join();
            }
            if (removal.joinable()) {
                removal.join();
            }
            watcher->clear();
        });
        QVERIFY(paused.tryAcquire(1, 5000));
        QVERIFY(!watcher->covers_directory(workspace.path()));
        if (change_policy) {
            watcher->set_policy_epoch(std::make_shared<path_name::Policy_epoch>([](const QString&) {
                return path_name::Directory_case_sensitivity::INSENSITIVE;
            }));
        }
        removal = std::thread([&] {
            watcher->clear();
            removed.store(true);
        });
        QVERIFY(retiring.tryAcquire(1, 5000));
        // Queries remain callable while retirement drains a paused scan worker.
        QVERIFY(!watcher->covers_directory(workspace.path()));
        QVERIFY(!removed.load());
        resume.release();
        removal.join();
        registration.join();
        QTRY_COMPARE_WITH_TIMEOUT(Native_watcher::active_thread_count_for_tests(), initial_threads, 3000);
        QVERIFY(!hook_timed_out.load());
        QCOMPARE(stale_callbacks.load(), 0);
        QCOMPARE(wrong_paths.load(), 0);
        const int callbacks_at_return = callbacks.load();
        const int attempts_at_return = Native_watcher::registration_attempt_count_for_tests();
        QVERIFY(write_file(workspace.filePath(QStringLiteral("after-removal.txt"))));
        QTest::qWait(1200);
        QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), attempts_at_return);
        QCOMPARE(callbacks.load(), callbacks_at_return);
    }
#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    void recursive_churn_retires_captured_policy_storage()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        QVERIFY(QDir().mkpath(root));
        detail::direct_limits_t limits;
        limits.plan_bytes = 1024 * 1024;
        detail::Direct_registry registry(limits);
        const auto client = registry.attach([](const Native_batch&) {});
        const auto policy = std::make_shared<vnm::path_name::Policy_epoch>();
        registry.replace(client, QList<Watch_spec>{{root, 0}}, Watch_mode::RECURSIVE,
            policy, {}, true);
        QVERIFY(registry.covers(client, root));
        const auto usage = policy->cache_usage();
        for (int index = 0; index != 12; ++index) {
            const auto branch = root + QStringLiteral("/generation-%1").arg(index);
            const auto nested = branch + QStringLiteral("/nested/leaf");
            QVERIFY(QDir().mkpath(nested));
#ifdef Q_OS_WIN
            QTRY_VERIFY_WITH_TIMEOUT(registry.resource_counts().covered_logical_directories == 5 &&
                registry.covers(client, root), 5000);
            QCOMPARE(registry.resource_counts().armed, 1);
#else
            QTRY_VERIFY_WITH_TIMEOUT(registry.resource_counts().armed == 5 &&
                registry.covers(client, root), 5000);
#endif
            QVERIFY(registry.resource_counts().plan_bytes <= limits.plan_bytes);
            QVERIFY(QDir(branch).removeRecursively());
#ifdef Q_OS_WIN
            QTRY_VERIFY_WITH_TIMEOUT(registry.resource_counts().covered_logical_directories == 2 &&
                registry.covers(client, root), 5000);
            QCOMPARE(registry.resource_counts().armed, 1);
#else
            QTRY_VERIFY_WITH_TIMEOUT(registry.resource_counts().armed == 2 &&
                registry.covers(client, root), 5000);
#endif
            QCOMPARE(policy->cache_usage().entries, usage.entries);
            QCOMPARE(policy->cache_usage().characters, usage.characters);
        }
        registry.detach(client);
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().plan_bytes, size_t(0), 5000);
    }

    void wide_directory_yields_to_another_root_before_expansion_finishes()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto large = workspace.filePath(QStringLiteral("large"));
        const auto small_root = workspace.filePath(QStringLiteral("small_root"));
        QVERIFY(QDir().mkpath(small_root));
        for (int index = 0; index != 512; ++index) {
            QVERIFY(QDir().mkpath(large + QStringLiteral("/child-%1/leaf").arg(index)));
        }
        detail::direct_limits_t limits;
        limits.scan_workers = 1;
        detail::Direct_registry registry(limits);
        const auto first = registry.attach([](const Native_batch&) {});
        const auto second = registry.attach([](const Native_batch&) {});
        QSemaphore first_result;
        QSemaphore second_result;
        QSemaphore resume;
        std::atomic_int results = 0;
        std::atomic_bool hook_timed_out = false;
        registry.set_expansion_observer_for_tests(first, [&](Native_watcher::Expansion_stage stage) {
            if (stage != Native_watcher::Expansion_stage::BEFORE_RESULT) {
                return;
            }
            const auto result = results.fetch_add(1);
            if (result < 2) {
                (result == 0 ? first_result : second_result).release();
                if (!resume.tryAcquire(1, 10000)) {
                    hook_timed_out.store(true);
                }
            }
        });
        const auto release = qScopeGuard([&] {
            resume.release(2);
            registry.detach(first);
            registry.detach(second);
        });
        const auto policy = std::make_shared<vnm::path_name::Policy_epoch>();
        registry.replace(first, QList<Watch_spec>{{large, 0}}, Watch_mode::RECURSIVE,
            policy, {}, false);
        QVERIFY(first_result.tryAcquire(1, 5000));
        registry.replace(second, QList<Watch_spec>{{small_root, 0}}, Watch_mode::RECURSIVE,
            policy, {}, false);
        QTRY_VERIFY_WITH_TIMEOUT(registry.resource_counts().scan_jobs >= 2, 5000);
        resume.release();
        QVERIFY(second_result.tryAcquire(1, 5000));
        // The first directory exceeds a scanner chunk. Its second chunk is held
        // while the other root must use the intervening FIFO worker turn.
        QCOMPARE(registry.expansion_count_for_tests(first), 0);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(second, small_root), 3000);
        QVERIFY(!registry.covers(first, large));
        QVERIFY(!hook_timed_out.load());
        resume.release();
    }

#endif

    void replacement_at_capacity_preserves_shared_interest()
    {
        // The final union fits exactly: replacing obsolete reasons must progress
        // without evicting shared interests or exceeding retiring-native budgets.
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        const auto old_path = root + QStringLiteral("/obsolete");
        const auto new_path = root + QStringLiteral("/replacement");
        const auto shared_path = root + QStringLiteral("/shared");
        for (const auto& path : {old_path, new_path, shared_path}) {
            QVERIFY(QDir().mkpath(path));
        }
        detail::direct_limits_t limits;
#ifdef Q_OS_WIN
        limits.registrations = 1;
#else
        limits.registrations = 4;
#endif
        detail::Direct_registry registry(limits);
        Native_capture first_capture;
        Native_capture shared_capture;
        const auto first = registry.attach([&](const Native_batch& batch) { first_capture.receive(batch); });
        const auto shared = registry.attach([&](const Native_batch& batch) { shared_capture.receive(batch); });
        auto policy = std::make_shared<vnm::path_name::Policy_epoch>();
        registry.replace(first, QList<Watch_spec>{{root, 0}}, Watch_mode::RECURSIVE, policy,
            [&](const QString&, const QString& path) { return path != new_path; }, true);
        registry.replace(shared, QList<Watch_spec>{{shared_path, 0}}, Watch_mode::DIRECT, policy, {}, true);
        auto report_initial_admission = qScopeGuard([&] {
            const auto first_status  = registry.coverage_status(first, root);
            const auto shared_status = registry.coverage_status(shared, shared_path);
            const auto counts        = registry.resource_counts();
            qWarning().noquote()
                << "Initial admission first state=" << int(first_status.state)
                << "diagnostic=" << first_status.diagnostic
                << "shared state=" << int(shared_status.state)
                << "diagnostic=" << shared_status.diagnostic;
            qWarning().noquote()
                << "Initial admission desired=" << counts.desired << "armed=" << counts.armed
                << "failed=" << counts.failed << "retiring=" << counts.retiring
                << "scan_pending=" << counts.scan_pending << "scan_failed=" << counts.scan_failed
                << "native_batches=" << counts.native_batches
                << "kernel_overflows=" << counts.kernel_overflows
                << "decoder_budget_losses=" << counts.decoder_budget_losses
                << "handoff_overflows=" << counts.handoff_overflows;
            qWarning().noquote()
                << "Initial admission armed directories=" << registry.armed_directories_for_tests();
            first_capture.report_batches("Initial admission first");
            shared_capture.report_batches("Initial admission shared");
        });
        QVERIFY(registry.covers(first, root));
        QVERIFY(registry.covers(shared, shared_path));
        QCOMPARE(registry.resource_counts().armed, int(limits.registrations));
        report_initial_admission.dismiss();
        const auto initial_revision = registry.revision(first, root);

        QSemaphore paused;
        QSemaphore resume;
        std::atomic_bool pause_once = true;
        std::atomic_bool hook_timed_out = false;
        registry.set_expansion_observer_for_tests(first, [&](Native_watcher::Expansion_stage stage) {
            if (stage == Native_watcher::Expansion_stage::BEFORE_RESULT && pause_once.exchange(false)) {
                paused.release();
                if (!resume.tryAcquire(1, 10000)) {
                    hook_timed_out.store(true);
                }
            }
        });
        const auto release = qScopeGuard([&] { resume.release(); });
        registry.replace(first, QList<Watch_spec>{{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(),
            [&](const QString&, const QString& path) { return path != old_path; }, false);
        QVERIFY(paused.tryAcquire(1, 5000));
        QVERIFY(!registry.covers(first, root));
        QVERIFY(registry.covers(shared, shared_path));
        QCOMPARE(registry.resource_counts().armed, int(limits.registrations));
        const auto shared_file = shared_path + QStringLiteral("/during-transition.txt");
        QVERIFY(write_file(shared_file));
        QVERIFY(shared_capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const auto& batch : batches) {
                for (const auto& event : batch.events) {
                    if (event.path == shared_file) {
                        return true;
                    }
                }
            }
            return false;
        }));
        resume.release();
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(first, root), 7000);
        QVERIFY(!hook_timed_out.load());
        QVERIFY(registry.revision(first, root) > initial_revision);
        const auto counts = registry.resource_counts();
        QCOMPARE(counts.desired, int(limits.registrations));
        QCOMPARE(counts.armed, int(limits.registrations));
        QCOMPARE(counts.failed, 0);
        QVERIFY(size_t(counts.armed + counts.retiring) <= limits.registrations);
        QVERIFY(counts.native_bytes <= limits.bytes);
        QVERIFY(registry.covers(shared, shared_path));
        const auto new_file = new_path + QStringLiteral("/after-transition.txt");
        QVERIFY(write_file(new_file));
        QVERIFY(first_capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const auto& batch : batches) {
                for (const auto& event : batch.events) {
                    if (event.path == new_file) {
                        return true;
                    }
                }
            }
            return false;
        }));

#ifdef Q_OS_WIN
        QTemporaryDir independent_workspace;
        QVERIFY(independent_workspace.isValid());
        const auto blocked_path = independent_workspace.filePath(QStringLiteral("content"));
#else
        const auto blocked_path = workspace.filePath(QStringLiteral("cannot-fit"));
#endif
        QVERIFY(QDir().mkpath(blocked_path));
        const auto blocked = registry.attach([](const Native_batch&) {});
        registry.replace(blocked, QList<Watch_spec>{{blocked_path, 0}}, Watch_mode::DIRECT, policy, {}, true);
        QVERIFY(!registry.covers(blocked, blocked_path));
        QVERIFY(registry.covers(first, root));
        QVERIFY(registry.covers(shared, shared_path));
        const auto refused = registry.resource_counts();
        QVERIFY(refused.failed > 0);
        QVERIFY(size_t(refused.armed + refused.retiring) <= limits.registrations);
        registry.detach(blocked);
        registry.detach(first);
        // Without the first client the Windows plan narrows to the shared root's
        // parent. At this capacity that anchor arms only after the broader one
        // retires, so the shared interest is restored rather than held throughout.
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(shared, shared_path), 7000);
        registry.detach(shared);
    }

#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    void precise_topology_preserves_only_existing_native_coverage_data()
    {
        QTest::addColumn<bool>("admitted");
        QTest::newRow("excluded-directory") << false;
        QTest::newRow("new-directory-readback") << true;
    }

    void precise_topology_preserves_only_existing_native_coverage()
    {
        // A Windows ancestor captures precise topology while enumeration runs.
        // A new logical directory still owes admission/readback; Linux must also
        // arm its own directory registration before coverage can be complete.
        QFETCH(bool, admitted);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        const auto other = workspace.filePath(QStringLiteral("other"));
        const auto child = root + QStringLiteral("/child");
        QVERIFY(QDir().mkpath(root));
        QVERIFY(QDir().mkpath(other));
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto unrelated = registry.attach([](const Native_batch&) {});
        QSemaphore paused;
        QSemaphore resume;
        std::atomic_bool pause_once = true;
        std::atomic_bool timed_out = false;
        const auto release = qScopeGuard([&] {
            resume.release();
            registry.detach(client);
            registry.detach(unrelated);
        });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(),
            [&](const QString&, const QString&) { return admitted; }, true);
        registry.replace(unrelated, {{other, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(registry.covers(client, root));
        const auto revision = registry.revision(client, root);
        const auto unrelated_revision = registry.revision(unrelated, other);
        const auto expansions = registry.expansion_count_for_tests(client);
        registry.set_expansion_observer_for_tests(client, [&](Native_watcher::Expansion_stage stage) {
            if (stage == Native_watcher::Expansion_stage::BEFORE_RESULT && pause_once.exchange(false)) {
                paused.release();
                if (!resume.tryAcquire(1, 10000)) {
                    timed_out.store(true);
                }
            }
        });
        QVERIFY(QDir().mkdir(child));
        QVERIFY(paused.tryAcquire(1, 5000));
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return batch.rescan_required && batch.rescan_event_paths_complete &&
                    std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                        return event.path == child && event.kind == Event_kind::CREATED;
                    });
            });
        }));
#ifdef Q_OS_WIN
        QCOMPARE(registry.coverage_status(client, root).state, Coverage_state::COVERED);
        QCOMPARE(registry.revision(client, root), revision);
#else
        QCOMPARE(registry.coverage_status(client, root).state, Coverage_state::PENDING);
        QVERIFY(registry.revision(client, root) > revision);
#endif
        // This file predates the child's logical registration. Completion must
        // publish a fresh readback obligation, even if its file event was absent.
        const auto before_admission = child + QStringLiteral("/before-admission.txt");
        QVERIFY(write_file(before_admission));
        resume.release();
        QTRY_VERIFY_WITH_TIMEOUT(registry.expansion_count_for_tests(client) > expansions, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        if (admitted) {
            QTRY_VERIFY_WITH_TIMEOUT(registry.covered_logical_directories_for_tests().contains(child), 5000);
            QTRY_VERIFY_WITH_TIMEOUT(registry.revision(client, root) > revision, 5000);
            QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
                return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                    return batch.coverage_revision > revision && batch.events.isEmpty() &&
                        batch.rescan_required && !batch.rescan_event_paths_complete;
                });
            }));
            const auto after_admission = child + QStringLiteral("/after-admission.txt");
            QVERIFY(write_file(after_admission));
            QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
                return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                    return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                        return event.path == after_admission;
                    });
                });
            }));
        }
#ifdef Q_OS_WIN
        else {
            QCOMPARE(registry.revision(client, root), revision);
        }
#endif
        QCOMPARE(registry.revision(unrelated, other), unrelated_revision);
        QVERIFY(!timed_out.load());
    }

    void local_topology_maintenance_preserves_unrelated_roots()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto stable = workspace.filePath(QStringLiteral("stable"));
        const auto active = workspace.filePath(QStringLiteral("active"));
        QVERIFY(QDir().mkpath(active));
        for (int index = 0; index != 24; ++index) {
            QVERIFY(QDir().mkpath(stable + QStringLiteral("/branch-%1/nested/leaf").arg(index)));
        }
        const auto marker_before = stable + QStringLiteral("/observation-marker-before.txt");
        const auto marker = stable + QStringLiteral("/observation-marker.txt");
        QVERIFY(write_file(marker_before));
        Native_capture stable_capture;
        Native_capture active_capture;
        detail::Direct_registry registry;
        const auto stable_client = registry.attach(
            [&](const Native_batch& batch) { stable_capture.receive(batch); });
        auto release_stable = qScopeGuard([&] { registry.detach(stable_client); });
        registry.replace(stable_client, {{stable, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        const auto settled = [&] {
            const auto resources = registry.resource_counts();
            return resources.scan_pending == 0 && resources.scan_jobs == 0 &&
                resources.scan_result_bytes == 0 && resources.retiring == 0 &&
                !registry.maintenance_pending_for_tests();
        };
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(stable_client, stable) && settled(), 5000);
        const auto stable_resources = registry.resource_counts();
        const auto active_client = registry.attach(
            [&](const Native_batch& batch) { active_capture.receive(batch); });
        auto release_active = qScopeGuard([&] { registry.detach(active_client); });
        const auto active_policy = std::make_shared<vnm::path_name::Policy_epoch>();
        const auto exclude_children = [](const QString&, const QString&) { return false; };
        registry.replace(active_client, {{active, 0}}, Watch_mode::RECURSIVE,
            active_policy, exclude_children, true);
        // The initial tree can still have native metadata notifications queued
        // when coverage becomes complete. Establish the measurement boundary by
        // observing a later marker on the same native source. A rename avoids
        // measuring between a marker file's create and subsequent write events.
        QVERIFY(QFile::rename(marker_before, marker));
        QVERIFY(stable_capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                    return event.path == marker;
                });
            });
        }));
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(active_client, active) && settled(), 5000);
        const auto initial_resources = registry.resource_counts();
        const auto stable_work = registry.maintenance_counts_for_tests(stable_client);
        const auto stable_expansions = registry.expansion_count_for_tests(stable_client);
        const auto stable_revision = registry.revision(stable_client, stable);
        const auto stable_publications = stable_capture.count();
        const auto active_expansions = registry.expansion_count_for_tests(active_client);
        const auto saw_event = [&](const QString& path, Event_kind kind) {
            return active_capture.wait_for([&](const QList<Native_batch>& batches) {
                return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                    return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                        return event.path == path && event.kind == kind;
                    });
                });
            });
        };

        // Await actual native delivery and completed expansion, rather than
        // assuming that a quiet wall-clock interval means work has finished.
        for (int index = 0; index != 3; ++index) {
            const auto child = active + QStringLiteral("/generation-%1").arg(index);
            const auto moved = active + QStringLiteral("/moved-%1").arg(index);
            QVERIFY(QDir().mkdir(child));
            QVERIFY(saw_event(child, Event_kind::CREATED));
            QVERIFY(QDir().rename(child, moved));
            QVERIFY(saw_event(moved, Event_kind::RENAMED));
            QVERIFY(QDir().rmdir(moved));
            QVERIFY(saw_event(moved, Event_kind::REMOVED));
        }
        QTRY_VERIFY_WITH_TIMEOUT(registry.expansion_count_for_tests(active_client) > active_expansions &&
            registry.covers(active_client, active) && settled(), 5000);
        const auto after_churn = registry.maintenance_counts_for_tests(stable_client);
        QCOMPARE(after_churn.identity_candidates, stable_work.identity_candidates);
        QCOMPARE(after_churn.binding_candidates, stable_work.binding_candidates);
        QCOMPARE(after_churn.resource_nodes, stable_work.resource_nodes);
        QCOMPARE(registry.expansion_count_for_tests(stable_client), stable_expansions);
        QCOMPARE(registry.revision(stable_client, stable), stable_revision);
        QCOMPARE(stable_capture.count(), stable_publications);
        QVERIFY(registry.covers(stable_client, stable));

        // The active client's replan must still admit existing descendants,
        // then release their ownership when its filter excludes them again.
        const auto admitted = active + QStringLiteral("/admitted");
        const auto leaf = admitted + QStringLiteral("/leaf");
        QVERIFY(QDir().mkpath(leaf));
        QVERIFY(saw_event(admitted, Event_kind::CREATED));
        registry.replace(active_client, {{active, 0}}, Watch_mode::RECURSIVE,
            active_policy, {}, true, 1);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covered_logical_directories_for_tests().contains(leaf) &&
            registry.covers(active_client, active) && settled(), 5000);
        QVERIFY(registry.resource_counts().logical_directories > initial_resources.logical_directories);
        registry.replace(active_client, {{active, 0}}, Watch_mode::RECURSIVE,
            active_policy, exclude_children, true, 2);
        QTRY_VERIFY_WITH_TIMEOUT(!registry.covered_logical_directories_for_tests().contains(leaf) &&
            registry.covers(active_client, active) && settled(), 5000);
        QCOMPARE(registry.resource_counts().logical_directories, initial_resources.logical_directories);
        QCOMPARE(registry.resource_counts().plan_bytes, initial_resources.plan_bytes);

        registry.detach(active_client);
        release_active.dismiss();
        QTRY_VERIFY_WITH_TIMEOUT(settled() &&
            registry.resource_counts().plan_bytes == stable_resources.plan_bytes &&
            registry.resource_counts().desired == stable_resources.desired &&
            registry.resource_counts().armed == stable_resources.armed, 5000);
        const auto remaining = registry.resource_counts();
        QCOMPARE(remaining.desired, stable_resources.desired);
        QCOMPARE(remaining.armed, stable_resources.armed);
        QCOMPARE(remaining.logical_directories, stable_resources.logical_directories);
        QCOMPARE(remaining.covered_logical_directories, stable_resources.covered_logical_directories);
        QCOMPARE(remaining.failed, 0);
        QVERIFY(registry.covers(stable_client, stable));
        const auto after_retirement = registry.maintenance_counts_for_tests(stable_client);
        QCOMPARE(after_retirement.identity_candidates, stable_work.identity_candidates);
        QCOMPARE(after_retirement.binding_candidates, stable_work.binding_candidates);
        QCOMPARE(after_retirement.resource_nodes, stable_work.resource_nodes);
        QCOMPARE(registry.expansion_count_for_tests(stable_client), stable_expansions);
        QCOMPARE(registry.revision(stable_client, stable), stable_revision);
        QCOMPARE(stable_capture.count(), stable_publications);

        registry.detach(stable_client);
        release_stable.dismiss();
        QTRY_VERIFY_WITH_TIMEOUT(settled() && registry.resource_counts().plan_bytes == 0 &&
            registry.resource_counts().native_bytes == 0, 5000);
        const auto released = registry.resource_counts();
        QCOMPARE(released.desired, 0);
        QCOMPARE(released.armed, 0);
        QCOMPARE(released.logical_directories, 0);
        QCOMPARE(released.covered_logical_directories, 0);
    }

    void failed_registration_recovers_once_and_releases_retry_state()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto set_failure = [](bool failed) {
#ifdef Q_OS_WIN
            // Leave transient identity queries available so this exercises
            // native registration retry, including after a prior recovery.
            detail::native_test_hooks::windows_arm_error.store(
                failed ? ERROR_ACCESS_DENIED : ERROR_SUCCESS);
#else
            Native_watcher::set_linux_add_watch_successes_before_failure_for_tests(
                failed ? 0 : -1);
#endif
        };
        set_failure(true);
        const auto reset_failure = qScopeGuard([&]() { set_failure(false); });
        std::atomic_int failures = 0;
        std::atomic_int recoveries = 0;
        std::atomic_uint64_t failed_revision = 0;
        std::atomic_uint64_t recovered_revision = 0;
        std::atomic_bool admission_claimed = false;
        auto watcher = std::make_unique<Native_watcher>(
            [&](const Native_batch& event) {
                if (event.initial_admission_only) {
                    admission_claimed.store(true);
                }
                if (event.reason == Native_reason::REGISTRATION_FAILED) {
                    failed_revision.store(event.coverage_revision);
                    ++failures;
                }
                if (event.reason == Native_reason::COVERAGE_CHANGED) {
                    recovered_revision.store(event.coverage_revision);
                    ++recoveries;
                }
            },
            Watch_mode::RECURSIVE);
        const int initial_attempts = Native_watcher::registration_attempt_count_for_tests();
        watcher->set_directories({workspace.path()});
        QCOMPARE(failures.load(), 1);
        QVERIFY(failed_revision.load() > 0);
        QVERIFY(!admission_claimed.load());
        QCOMPARE(watcher->coverage_revision(workspace.path()), failed_revision.load());
        for (int i = 0; i < 5; ++i) {
            watcher->set_directories({workspace.path()});
        }
#ifdef Q_OS_WIN
        QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), initial_attempts + 1);
#else
        QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), initial_attempts + 2);
#endif
        QTest::qWait(6500);
        const int attempts = Native_watcher::registration_attempt_count_for_tests() - initial_attempts;
        // Each physical registration retries at the same bounded cadence.
#ifdef Q_OS_WIN
        QVERIFY(attempts >= 4 && attempts <= 8);
#else
        QVERIFY(attempts >= 4 && attempts <= 16);
#endif
        QCOMPARE(failures.load(), 1);
        QCOMPARE(recoveries.load(), 0);
        QCOMPARE(watcher->coverage_revision(workspace.path()), failed_revision.load());

        set_failure(false);
        QTRY_VERIFY_WITH_TIMEOUT(watcher->covers_directory(workspace.path()), 8000);
        QTRY_COMPARE_WITH_TIMEOUT(recoveries.load(), 1, 1000);
        QVERIFY(recovered_revision.load() > failed_revision.load());
        QVERIFY(!admission_claimed.load());
        QCOMPARE(watcher->coverage_revision(workspace.path()), recovered_revision.load());

        // Removing an unresolved subscription and destroying an owner both
        // cancel their retry deadlines, even while the native error persists.
        watcher->clear();
        set_failure(true);
        watcher->set_directories({workspace.path()});
        watcher->set_directories({});
        const int removed_attempts = Native_watcher::registration_attempt_count_for_tests();
        QTest::qWait(1500);
        QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), removed_attempts);
        watcher->set_directories({workspace.path()});
        watcher.reset();
        const int closed_attempts = Native_watcher::registration_attempt_count_for_tests();
        QTest::qWait(1500);
        QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), closed_attempts);
    }
#endif

#ifdef Q_OS_LINUX
    void special_files_do_not_block_recursive_coverage_data()
    {
        QTest::addColumn<bool>("discovery");
        QTest::newRow("recursive") << false;
        QTest::newRow("discovery-recursive") << true;
    }

    void special_files_do_not_block_recursive_coverage()
    {
        // Oracle: coverage obligations exist only for directories. A FIFO or a
        // socket in a watched tree is ordinary directory content.
        QFETCH(bool, discovery);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString nested = workspace.filePath(QStringLiteral("nested"));
        QVERIFY(QDir().mkpath(nested));
        QCOMPARE(mkfifo(QFile::encodeName(nested + QStringLiteral("/pipe")).constData(), 0600), 0);
        const int socket_descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        QVERIFY(socket_descriptor >= 0);
        const auto close_socket = qScopeGuard([&]() { close(socket_descriptor); });
        const QByteArray socket_path = QFile::encodeName(workspace.filePath(QStringLiteral("socket")));
        sockaddr_un address{};
        QVERIFY(size_t(socket_path.size()) < sizeof(address.sun_path));
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, socket_path.constData(), size_t(socket_path.size()));
        QCOMPARE(bind(socket_descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), 0);

        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            discovery ? Watch_mode::DISCOVERY_RECURSIVE : Watch_mode::RECURSIVE);
        watcher.set_directories({workspace.path()});
        QVERIFY(watcher.covers_directory(workspace.path()));
        QCOMPARE(watcher.resource_counts().failed, 0);

        // A directory creation rewalks the tree, so the walk meets a later FIFO too.
        const QString late_pipe = workspace.filePath(QStringLiteral("late-pipe"));
        QCOMPARE(mkfifo(QFile::encodeName(late_pipe).constData(), 0600), 0);
        const int rebuilds_before_directory = watcher.expansion_count_for_tests();
        QVERIFY(QDir().mkpath(workspace.filePath(QStringLiteral("late-directory"))));
        QTRY_VERIFY_WITH_TIMEOUT(
            watcher.expansion_count_for_tests() > rebuilds_before_directory, 5000);
        const QString path = nested + QStringLiteral("/tracked.txt");
        QVERIFY(write_file(path));
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const Native_batch& batch : batches) {
                for (const Event& event : batch.events) {
                    if (event.path == path) {
                        return true;
                    }
                }
            }
            return false;
        }));
        QVERIFY(watcher.covers_directory(workspace.path()));
        QCOMPARE(watcher.resource_counts().failed, 0);
    }

    void discovery_rescans_only_for_directory_topology_data()
    {
        QTest::addColumn<QString>("change");
        QTest::addColumn<QString>("relative_path");
        QTest::addColumn<int>("kind");
        QTest::addColumn<int>("entry_type");
        QTest::addColumn<bool>("topology");
        const int created   = int(Event_kind::CREATED);
        const int removed   = int(Event_kind::REMOVED);
        const int renamed   = int(Event_kind::RENAMED);
        const int directory = int(Entry_type::DIRECTORY);
        const int file      = int(Entry_type::NON_DIRECTORY);
        QTest::newRow("file-create")
            << "create-file"      << "notes.txt"          << created << file      << false;
        QTest::newRow("file-remove")
            << "remove-file"      << "existing.txt"       << removed << file      << false;
        QTest::newRow("file-rename")
            << "rename-file"      << "renamed.txt"        << renamed << file      << false;
        QTest::newRow("directory-create")
            << "create-directory" << "created-directory"  << created << directory << true;
        QTest::newRow("directory-remove")
            << "remove-directory" << "existing-directory" << removed << directory << true;
        QTest::newRow("git-marker-file-create")
            << "create-file"      << "candidate/.git"     << created << file      << true;
        QTest::newRow("git-marker-directory-create")
            << "create-directory" << "candidate/.git"     << created << directory << true;
        QTest::newRow("git-marker-file-remove")
            << "remove-file"      << "worktree/.git"      << removed << file      << true;
    }

    void discovery_rescans_only_for_directory_topology()
    {
        // Oracle: the repository-discovery contract Logonomic's own watcher kept.
        // Only a directory, or a `.git` marker of either type, appearing or
        // disappearing changes which repositories exist; other entries are
        // detail for the subscriber's classifier and must not force a rescan.
        QFETCH(QString, change);
        QFETCH(QString, relative_path);
        QFETCH(int, kind);
        QFETCH(int, entry_type);
        QFETCH(bool, topology);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QDir root(workspace.path());
        QVERIFY(write_file(root.filePath(QStringLiteral("existing.txt"))));
        QVERIFY(root.mkpath(QStringLiteral("existing-directory")));
        QVERIFY(root.mkpath(QStringLiteral("candidate")));
        QVERIFY(root.mkpath(QStringLiteral("worktree")));
        QVERIFY(write_file(root.filePath(QStringLiteral("worktree/.git")), QByteArray("gitdir: elsewhere\n")));

        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::DISCOVERY_RECURSIVE);
        watcher.set_directories({workspace.path()});
        QVERIFY(watcher.covers_directory(workspace.path()));
        const qsizetype first_batch = capture.count();
        const int rebuilds_before   = watcher.expansion_count_for_tests();

        const QString path = root.filePath(relative_path);
        if (change == QStringLiteral("create-file")) {
            QVERIFY(write_file(path));
        }
        else
        if (change == QStringLiteral("remove-file")) {
            QVERIFY(QFile::remove(path));
        }
        else
        if (change == QStringLiteral("rename-file")) {
            QVERIFY(QFile::rename(root.filePath(QStringLiteral("existing.txt")), path));
        }
        else
        if (change == QStringLiteral("create-directory")) {
            QVERIFY(root.mkdir(relative_path));
        }
        else {
            QVERIFY(root.rmdir(relative_path));
        }

        bool rescan_required = false;
        std::optional<Event> observed;
        QStringList observations;
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            rescan_required = false;
            observations.clear();
            for (const Native_batch& batch : batches.mid(first_batch)) {
                observations.append(QStringLiteral("root=%1 scope=%2 rescan=%3 paths_complete=%4 reason=%5 diagnostic=%6")
                    .arg(batch.root, batch.scope).arg(batch.rescan_required)
                    .arg(batch.rescan_event_paths_complete).arg(int(batch.reason)).arg(batch.diagnostic));
                rescan_required = rescan_required || batch.rescan_required;
                for (const Event& event : batch.events) {
                    observations.append(QStringLiteral("kind=%1 type=%2 path=%3 old_path=%4")
                        .arg(int(event.kind)).arg(int(event.entry_type)).arg(event.path, event.old_path));
                    if (event.path == path && int(event.kind) == kind) {
                        observed = event;
                        return true;
                    }
                }
            }
            return false;
        }));
        QCOMPARE(int(observed->entry_type), entry_type);
        if (rescan_required != topology) {
            qWarning().noquote() << observations.join(QLatin1Char('\n'));
        }
        QCOMPARE(rescan_required, topology);
        if (topology) {
            QTRY_VERIFY_WITH_TIMEOUT(watcher.expansion_count_for_tests() > rebuilds_before, 5000);
            QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(workspace.path()), 5000);
        }
        else {
            QCOMPARE(watcher.expansion_count_for_tests(), rebuilds_before);
        }
    }

    void queue_overflow_reconciles_retained_registrations_data()
    {
        QTest::addColumn<bool>("discovery");
        QTest::newRow("recursive")           << false;
        QTest::newRow("discovery-recursive") << true;
    }

    void queue_overflow_reconciles_retained_registrations()
    {
        // Oracle: IN_Q_OVERFLOW loses event detail, not the watches, so the
        // registrations remain allocated while recursive topology is reconciled.
        QFETCH(bool, discovery);
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        QVERIFY(QDir().mkpath(workspace.filePath(QStringLiteral("nested"))));
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            discovery ? Watch_mode::DISCOVERY_RECURSIVE : Watch_mode::RECURSIVE);
        watcher.set_directories({workspace.path()});
        QVERIFY(watcher.covers_directory(workspace.path()));
        const int kernel_watches = watcher.linux_kernel_watch_count_for_tests();

        watcher.inject_linux_overflow_for_tests();
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const Native_batch& batch : batches) {
                if (batch.reason == Native_reason::QUEUE_OVERFLOW) {
                    return
                        batch.rescan_required           &&
                        batch.root  == workspace.path() &&
                        batch.scope == workspace.path();
                }
            }
            return false;
        }));
        QCOMPARE(watcher.linux_kernel_watch_count_for_tests(), kernel_watches);
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(workspace.path()), 5000);
    }

    void moved_root_releases_its_watch_descriptors()
    {
        // Oracle: a watched root that is moved away is no longer the configured
        // path, so its kernel watches must be released; a directory recreated at
        // that path is watched in their place, and no descriptor leaks.
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        QDir parent(workspace.path());
        const QString root_path  = parent.filePath(QStringLiteral("root"));
        const QString moved_path = parent.filePath(QStringLiteral("root-moved"));
        const QString beta_path  = parent.filePath(QStringLiteral("root/beta"));
        const QString gamma_path = parent.filePath(QStringLiteral("root/beta/gamma"));
        QVERIFY(parent.mkpath(QStringLiteral("root/alpha")));
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::DISCOVERY_RECURSIVE);
        watcher.set_directories({root_path});
        QVERIFY(watcher.covers_directory(root_path));
        // The root's parent, the root and alpha.
        QCOMPARE(watcher.linux_kernel_watch_count_for_tests(), 3);

        // Each step waits for the event its predecessor's watch reports, so the
        // next change lands under a watch rather than inside a rewalk.
        const auto wait_for_event = [&](Event_kind kind, const QString& path) {
            return capture.wait_for([&](const QList<Native_batch>& batches) {
                for (const Native_batch& batch : batches) {
                    for (const Event& event : batch.events) {
                        if (event.kind == kind && (event.path == path || event.old_path == path)) {
                            return true;
                        }
                    }
                }
                return false;
            });
        };
        QVERIFY(parent.rename(QStringLiteral("root"), QStringLiteral("root-moved")));
        QVERIFY(wait_for_event(Event_kind::RENAMED, root_path));
        // Only the parent stays watched, to see the root reappear.
        QTRY_COMPARE_WITH_TIMEOUT(watcher.linux_kernel_watch_count_for_tests(), 1, 5000);

        QVERIFY(parent.mkdir(QStringLiteral("root")));
        QVERIFY(wait_for_event(Event_kind::CREATED, root_path));
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(root_path), 5000);
        QVERIFY(parent.mkdir(QStringLiteral("root/beta")));
        QVERIFY(wait_for_event(Event_kind::CREATED, beta_path));
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(root_path), 5000);
        QVERIFY(parent.mkdir(QStringLiteral("root/beta/gamma")));
        QVERIFY(wait_for_event(Event_kind::CREATED, gamma_path));
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(root_path), 5000);
        // The parent, the recreated root, beta and gamma; nothing under root-moved.
        QTRY_COMPARE_WITH_TIMEOUT(watcher.linux_kernel_watch_count_for_tests(), 4, 5000);
        QVERIFY(QDir(moved_path).exists(QStringLiteral("alpha")));
    }

    void persistent_partial_failure_bounds_native_retries()
    {
        // Oracle: incomplete coverage stays reported and retried, but a failure that
        // persists must not rewalk the whole tree on every recovery tick.
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString child = workspace.filePath(QStringLiteral("child"));
        QVERIFY(QDir().mkpath(child));
        QVERIFY(QDir().mkpath(workspace.filePath(QStringLiteral("sibling"))));
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::RECURSIVE);
        watcher.set_directories({workspace.path()});
        QVERIFY(watcher.covers_directory(workspace.path()));

        const auto reset_failure = qScopeGuard([]() {
            Native_watcher::set_linux_add_watch_successes_before_failure_for_tests(-1);
        });
        Native_watcher::set_linux_add_watch_successes_before_failure_for_tests(0);
        watcher.invalidate_linux_content_watches_for_tests();
        QTRY_VERIFY_WITH_TIMEOUT(!watcher.covers_directory(workspace.path()), 5000);
        const int expansions_at_failure = watcher.expansion_count_for_tests();
        const int attempts_at_failure = Native_watcher::registration_attempt_count_for_tests();
        std::this_thread::sleep_for(std::chrono::milliseconds(3000));
        const int retries = Native_watcher::registration_attempt_count_for_tests() - attempts_at_failure;
        // Root loss retires its obsolete descendants. Retry only the missing
        // root, without enumerating again while native arming is unavailable.
        QVERIFY2(retries >= 2 && retries <= 4, qPrintable(QStringLiteral("retries=%1").arg(retries)));
        QCOMPARE(watcher.expansion_count_for_tests(), expansions_at_failure);
        QVERIFY(!watcher.covers_directory(workspace.path()));
        QVERIFY(watcher.resource_counts().failed > 0);

        Native_watcher::set_linux_add_watch_successes_before_failure_for_tests(-1);
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(workspace.path()), 7000);
        const QString path = child + QStringLiteral("/after-recovery.txt");
        QVERIFY(write_file(path));
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const Native_batch& batch : batches) {
                for (const Event& event : batch.events) {
                    if (event.path == path) {
                        return true;
                    }
                }
            }
            return false;
        }));
    }
#endif

    void paths_arrive_without_a_caller_event_loop()
    {
        // Oracle: adopted path-preserving native delivery and hidden coverage.
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString hidden = directory.filePath(QStringLiteral(".hidden/nested"));
        QVERIFY(QDir().mkpath(hidden));
        const QString path = hidden + QStringLiteral("/tracked.txt");
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::RECURSIVE);
        watcher.set_directories({directory.path()});
        QVERIFY(watcher.covers_directory(directory.path()));
        const auto revision = watcher.coverage_revision(directory.path());
        QVERIFY(write_file(path));
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const Native_batch& batch : batches) {
                for (const Event& event : batch.events) {
                    if (event.path == path) {
                        return batch.root == directory.path() &&
                            batch.scope == directory.path() &&
                            batch.coverage_revision == revision;
                    }
                }
            }
            return false;
        }));
        QVERIFY(watcher.resource_counts().armed > 0);
        QVERIFY(watcher.resource_counts().native_threads > 0);
    }

    void rename_keeps_both_available_endpoints_data()
    {
        QTest::addColumn<bool>("move_between_directories");
        QTest::newRow("same-directory-rename") << false;
        QTest::newRow("move-between-directories") << true;
    }

    void rename_keeps_both_available_endpoints()
    {
        // Oracle: native rename endpoints survive conversion into bounded batches.
        QFETCH(bool, move_between_directories);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QVERIFY(QDir().mkpath(directory.filePath(QStringLiteral("left"))));
        QVERIFY(QDir().mkpath(directory.filePath(QStringLiteral("right"))));
        const QString before = directory.filePath(QStringLiteral("left/before.txt"));
        const QString after = directory.filePath(move_between_directories
            ? QStringLiteral("right/after.txt") : QStringLiteral("left/after.txt"));
        QVERIFY(write_file(before));
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::RECURSIVE);
        watcher.set_directories({directory.path()});
        QVERIFY(watcher.covers_directory(directory.path()));
        QVERIFY(QFile::rename(before, after));
        QString observed;
        const bool delivered = capture.wait_for([&](const QList<Native_batch>& batches) {
            observed.clear();
            bool old_seen = false;
            bool new_seen = false;
            for (const Native_batch& batch : batches) {
                for (const Event& event : batch.events) {
                    observed += QStringLiteral("kind=%1 path=%2 old=%3 rescan=%4\n")
                        .arg(int(event.kind)).arg(event.path, event.old_path).arg(batch.rescan_required);
                    if (event.kind != Event_kind::RENAMED) {
                        // Windows can represent a cross-directory move as a
                        // removal and creation. Both precise endpoints remain
                        // required; a same-directory rename must retain its kind.
                        if (move_between_directories) {
                            old_seen |= event.kind == Event_kind::REMOVED && event.path == before;
                            new_seen |= event.kind == Event_kind::CREATED && event.path == after;
                        }
                        continue;
                    }
                    old_seen = old_seen || event.old_path == before;
#ifdef Q_OS_MACOS
                    // FSEvents preserves both named endpoints but supplies no orientation.
                    old_seen = old_seen || event.path == before;
#endif
                    new_seen = new_seen || event.path == after;
                    if ((event.path.isEmpty() || event.old_path.isEmpty()) &&
                        !batch.rescan_required)
                    {
                        return false;
                    }
                }
            }
            return old_seen && new_seen;
        });
        QVERIFY2(delivered, qPrintable(observed));
    }

#ifdef Q_OS_WIN
    void direct_control_port_allocation_recovers_without_reconfiguration()
    {
        // A transient OS allocation failure leaves live interests incomplete;
        // releasing the fault must restore coverage without another replace call.
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const int initial_threads = Native_watcher::active_thread_count_for_tests();
        Native_watcher::set_windows_completion_port_error_for_tests(ERROR_NOT_ENOUGH_MEMORY);
        const auto reset_failure = qScopeGuard([] {
            Native_watcher::set_windows_completion_port_error_for_tests(ERROR_SUCCESS);
        });
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::DIRECT);
        watcher.set_directories({directory.path()});
        QVERIFY(!watcher.covers_directory(directory.path()));
        QVERIFY(watcher.resource_counts().failed > 0);
        const uint64_t failed_revision = watcher.coverage_revision(directory.path());
        QVERIFY(failed_revision > 0);
        QVERIFY(capture.wait_for([](const QList<Native_batch>& batches) {
            for (const auto& batch : batches) {
                if (batch.rescan_required && batch.reason == Native_reason::REGISTRATION_FAILED) {
                    return true;
                }
            }
            return false;
        }));
        Native_watcher::set_windows_completion_port_error_for_tests(ERROR_SUCCESS);
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(directory.path()), 5000);
        QVERIFY(watcher.coverage_revision(directory.path()) > failed_revision);
        const QString final_path = directory.filePath(QStringLiteral("after-port-recovery.txt"));
        QVERIFY(write_file(final_path));
        QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
            for (const auto& batch : batches) {
                for (const auto& event : batch.events) {
                    if (event.path == final_path) {
                        return true;
                    }
                }
            }
            return false;
        }));
        watcher.clear();
        QCOMPARE(Native_watcher::active_thread_count_for_tests(), initial_threads);
    }

    void replaced_root_recovers_the_configured_path_data()
    {
        QTest::addColumn<int>("watch_mode");
        QTest::addColumn<bool>("missing_root_interval");
        QTest::addColumn<int>("file_id_error");
        QTest::newRow("direct")
            << int(Watch_mode::DIRECT)              << false << int(ERROR_SUCCESS);
        QTest::newRow("recursive")
            << int(Watch_mode::RECURSIVE)           << false << int(ERROR_SUCCESS);
        QTest::newRow("discovery-recursive")
            << int(Watch_mode::DISCOVERY_RECURSIVE) << false << int(ERROR_SUCCESS);
        QTest::newRow("missing-root-backoff")
            << int(Watch_mode::DISCOVERY_RECURSIVE) << true  << int(ERROR_SUCCESS);
        QTest::newRow("unsupported-128-id")
            << int(Watch_mode::DISCOVERY_RECURSIVE) << false << int(ERROR_NOT_SUPPORTED);
        QTest::newRow("invalid-128-id")
            << int(Watch_mode::DISCOVERY_RECURSIVE) << false << int(ERROR_INVALID_PARAMETER);
    }

    void replaced_root_recovers_the_configured_path()
    {
        // A native handle still names the moved directory. Coverage must follow
        // the configured path, reconcile its replacement and ignore the old tree.
        QFETCH(int, watch_mode);
        QFETCH(bool, missing_root_interval);
        QFETCH(int, file_id_error);
        using namespace std::chrono_literals;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        QDir parent(workspace.path());
        const QString root_path  = parent.filePath(QStringLiteral("root"));
        const QString moved_path = parent.filePath(QStringLiteral("root-moved"));
        QVERIFY(parent.mkdir(QStringLiteral("root")));
        const int initial_threads = Native_watcher::active_thread_count_for_tests();
        Native_watcher::set_windows_file_id_error_for_tests(uint32_t(file_id_error));
        const auto reset_identity_error = qScopeGuard([] {
            Native_watcher::set_windows_file_id_error_for_tests(ERROR_SUCCESS);
        });
        Service service;
        auto channel = std::make_shared<Wait_channel>();
        Subscription_options options;
        options.directories = {{root_path, 0}};
        options.mode = static_cast<Watch_mode>(watch_mode);
        // This gate requires the replacement's child directory. Declare that
        // physical depth instead of relying on the former Windows subtree read.
        options.directories.front().maximum_depth = 1;
        options.interval = 50ms;
        auto subscription = service.subscribe(options, channel);
        const auto wait_without_event_loop = [](const std::function<bool()>& predicate) {
            const auto deadline = std::chrono::steady_clock::now() + 5s;
            while (!predicate()) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    return false;
                }
                std::this_thread::sleep_for(5ms);
            }
            return true;
        };
        QVERIFY(wait_without_event_loop([&] { return subscription.covers_directory(root_path); }));
        while (auto delivery = channel->wait(50ms)) {
            subscription.acknowledge(delivery->batch.capture);
            delivery->completion.complete();
        }
        const auto initial_revision = subscription.coverage_revision(root_path);
        const int initial_attempts = Native_watcher::registration_attempt_count_for_tests();
        QVERIFY(parent.rename(QStringLiteral("root"), QStringLiteral("root-moved")));
        if (missing_root_interval) {
            // The ancestor stays armed while the absent configured root uses
            // bounded transient identity queries instead of new native watches.
            bool saw_missing_reconciliation = false;
            QVERIFY(wait_without_event_loop([&] {
                if (auto delivery = channel->wait(10ms)) {
                    saw_missing_reconciliation |= delivery->batch.rescan_required;
                    subscription.acknowledge(delivery->batch.capture);
                    delivery->completion.complete();
                }
                return !subscription.covers_directory(root_path) &&
                    subscription.coverage_revision(root_path) > initial_revision && saw_missing_reconciliation;
            }));
            const int initial_identity_failures =
                detail::native_test_hooks::windows_failed_identity_opens.load();
            std::this_thread::sleep_for(6500ms);
            const int identity_failures =
                detail::native_test_hooks::windows_failed_identity_opens.load() - initial_identity_failures;
            QVERIFY(identity_failures >= 4 && identity_failures <= 8);
            QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), initial_attempts);
            QCOMPARE(service.resource_counts().armed, 1);
            QVERIFY(!subscription.covers_directory(root_path));
            while (auto delivery = channel->wait(50ms)) {
                subscription.acknowledge(delivery->batch.capture);
                delivery->completion.complete();
            }
        }
        QVERIFY(parent.mkpath(QStringLiteral("root/new-repository/.git")));
        QVERIFY(write_file(root_path + QStringLiteral("/new-repository/during-replacement.txt")));
        QVERIFY(write_file(moved_path + QStringLiteral("/retired-tree.txt")));
        bool saw_reconciliation = false;
        bool saw_retired_tree   = false;
        const bool replacement_covered = wait_without_event_loop([&] {
            if (auto delivery = channel->wait(10ms)) {
                saw_reconciliation |= delivery->batch.rescan_required;
                for (const Event& event : delivery->batch.events) {
                    saw_retired_tree |= event.path == root_path + QStringLiteral("/retired-tree.txt");
                }
                subscription.acknowledge(delivery->batch.capture);
                delivery->completion.complete();
            }
            return subscription.covers_directory(root_path) &&
                subscription.coverage_revision(root_path) > initial_revision && saw_reconciliation;
        });
        qInfo() << "Root replacement observation" << "covered=" << subscription.covers_directory(root_path)
                << "before_revision=" << initial_revision
                << "after_revision=" << subscription.coverage_revision(root_path)
                << "rescan=" << saw_reconciliation << "retired_tree_relabelled=" << saw_retired_tree;
        QVERIFY(replacement_covered);
        QVERIFY(!saw_retired_tree);
        const QString final_path = root_path +
            (options.mode == Watch_mode::DIRECT
                ? QStringLiteral("/live.txt")
                : QStringLiteral("/new-repository/live.txt"));
        QVERIFY(write_file(final_path));
        bool saw_final_path = false;
        QVERIFY(wait_without_event_loop([&] {
            if (auto delivery = channel->wait(10ms)) {
                for (const Event& event : delivery->batch.events) {
                    saw_final_path |= event.path == final_path;
                }
                delivery->completion.complete();
            }
            return saw_final_path;
        }));
        subscription.reset();
        QVERIFY(wait_without_event_loop([&] {
            const auto statistics = service.statistics();
            return statistics.subscriptions == 0 && statistics.pending_registrations == 0 &&
                statistics.retiring_groups == 0 &&
                Native_watcher::active_thread_count_for_tests() == initial_threads;
        }));
    }

    void service_runtime_failure_recovers_or_retires_data()
    {
        QTest::addColumn<bool>("cancel_pending_recovery");
        QTest::newRow("autonomous-rearm-without-caller-loop") << false;
        QTest::newRow("cancel-pending-recovery") << true;
    }

    void service_runtime_failure_recovers_or_retires()
    {
        QFETCH(bool, cancel_pending_recovery);
        using namespace std::chrono_literals;
        QTemporaryDir root;
        QVERIFY(root.isValid());
        const int initial_threads = Native_watcher::active_thread_count_for_tests();
        Service service;
        auto channel = std::make_shared<Wait_channel>();
        Subscription_options options;
        options.directories = {{root.path(), 0}};
        options.mode = Watch_mode::DIRECT;
        options.interval = 50ms;
        auto subscription = service.subscribe(options, channel);
        const auto wait_without_event_loop = [](const std::function<bool()>& predicate) {
            const auto deadline = std::chrono::steady_clock::now() + 5s;
            while (!predicate()) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    return false;
                }
                std::this_thread::sleep_for(5ms);
            }
            return true;
        };
        QVERIFY(wait_without_event_loop([&] { return subscription.covers_directory(root.path()); }));
        while (auto delivery = channel->wait(100ms)) {
            (void)QDir(root.path()).entryList(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot);
            QVERIFY(subscription.acknowledge(delivery->batch.capture));
            delivery->completion.complete();
        }
        const int initial_attempts = Native_watcher::registration_attempt_count_for_tests();
        const auto initial_revision = subscription.coverage_revision(root.path());
        const auto reset_hooks = qScopeGuard([] {
            Native_watcher::set_windows_completion_error_for_tests(ERROR_SUCCESS);
            detail::native_test_hooks::windows_arm_error.store(ERROR_SUCCESS);
        });
        if (cancel_pending_recovery) {
            detail::native_test_hooks::windows_arm_error.store(ERROR_ACCESS_DENIED);
        }
        Native_watcher::set_windows_completion_error_for_tests(ERROR_ACCESS_DENIED);
        QVERIFY(write_file(root.filePath(QStringLiteral("fault-trigger.txt"))));
        QVERIFY(wait_without_event_loop([&] {
            return Native_watcher::registration_attempt_count_for_tests() > initial_attempts;
        }));
        Native_watcher::set_windows_completion_error_for_tests(ERROR_SUCCESS);

        if (cancel_pending_recovery) {
            QVERIFY(!subscription.covers_directory(root.path()));
            const auto status = subscription.coverage_status(root.path());
            QCOMPARE(status.state, Coverage_state::FAILED);
            QVERIFY(status.diagnostic.contains(QString::number(ERROR_ACCESS_DENIED)));
            subscription.reset();
            QVERIFY(wait_without_event_loop([&] {
                const auto statistics = service.statistics();
                return statistics.subscriptions == 0 && statistics.pending_registrations == 0 &&
                    statistics.retiring_groups == 0 &&
                    Native_watcher::active_thread_count_for_tests() == initial_threads;
            }));
            const int retired_attempts = Native_watcher::registration_attempt_count_for_tests();
            std::this_thread::sleep_for(1200ms);
            QCOMPARE(Native_watcher::registration_attempt_count_for_tests(), retired_attempts);
            QVERIFY(!channel->wait(10ms));
            return;
        }

        QVERIFY(wait_without_event_loop([&] { return subscription.covers_directory(root.path()); }));
        QVERIFY(subscription.coverage_revision(root.path()) > initial_revision);
        bool saw_reconciliation = false;
        while (auto delivery = channel->wait(100ms)) {
            saw_reconciliation |= delivery->batch.rescan_required;
            (void)QDir(root.path()).entryList(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot);
            subscription.acknowledge(delivery->batch.capture);
            delivery->completion.complete();
        }
        QVERIFY(saw_reconciliation);
        const QString final_path = root.filePath(QStringLiteral("after-recovery.txt"));
        QVERIFY(write_file(final_path));
        bool saw_final_path = false;
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (!saw_final_path && std::chrono::steady_clock::now() < deadline) {
            if (auto delivery = channel->wait(50ms)) {
                for (const Event& event : delivery->batch.events) {
                    saw_final_path |= event.path == final_path;
                }
                delivery->completion.complete();
            }
        }
        QVERIFY(saw_final_path);
    }

    void windows_extended_detail_has_event_time_entry_types()
    {
        namespace detail = vnm::filesystem_observation::detail;
        const QString root = QStringLiteral("C:/watched");
        const auto decode = [&](const QByteArray& bytes) {
            return detail::decode_windows_extended_notifications(root,
                bytes.constData(), static_cast<uint32_t>(bytes.size())).batch;
        };
        // Three-character names produce a 4-byte-only aligned successor;
        // the record's 64-bit fields must not require 8-byte source alignment.
        const auto batch = decode(windows_extended_records({
            {FILE_ACTION_ADDED, QStringLiteral("abc"), FILE_ATTRIBUTE_NORMAL},
            {FILE_ACTION_REMOVED, QStringLiteral("gone"), FILE_ATTRIBUTE_DIRECTORY},
            {FILE_ACTION_RENAMED_OLD_NAME, QStringLiteral("old"), FILE_ATTRIBUTE_DIRECTORY},
            {FILE_ACTION_RENAMED_NEW_NAME, QStringLiteral("new"), FILE_ATTRIBUTE_DIRECTORY}}));
        QCOMPARE(batch.events.size(), 3);
        QCOMPARE(batch.events[0].entry_type, Entry_type::NON_DIRECTORY);
        QCOMPARE(batch.events[1].entry_type, Entry_type::DIRECTORY);
        QCOMPARE(batch.events[1].kind, Event_kind::REMOVED);
        QCOMPARE(batch.events[2].entry_type, Entry_type::DIRECTORY);
        QCOMPARE(batch.events[2].old_path, root + QStringLiteral("/old"));
        QCOMPARE(batch.events[2].path, root + QStringLiteral("/new"));
        QVERIFY(!batch.rescan_required);
        const auto mismatched = decode(windows_extended_records({
            {FILE_ACTION_RENAMED_OLD_NAME, QStringLiteral("file"), FILE_ATTRIBUTE_NORMAL},
            {FILE_ACTION_RENAMED_NEW_NAME, QStringLiteral("directory"), FILE_ATTRIBUTE_DIRECTORY}}));
        QCOMPARE(mismatched.events.size(), 2);
        QCOMPARE(mismatched.events[0].entry_type, Entry_type::NON_DIRECTORY);
        QCOMPARE(mismatched.events[1].entry_type, Entry_type::DIRECTORY);
        QVERIFY(mismatched.events[0].path.isEmpty());
        QVERIFY(mismatched.events[1].old_path.isEmpty());
        QVERIFY(mismatched.rescan_required);

        const auto valid = windows_extended_records({
            {FILE_ACTION_ADDED, QStringLiteral("entry"), FILE_ATTRIBUTE_NORMAL}});
        QVERIFY(decode({}).rescan_required);
        QVERIFY(decode(valid.first(offsetof(FILE_NOTIFY_EXTENDED_INFORMATION, FileName) - 1)).rescan_required);
        auto malformed = valid;
        const DWORD odd_name_bytes = 3;
        std::memcpy(malformed.data() + offsetof(FILE_NOTIFY_EXTENDED_INFORMATION, FileNameLength),
            &odd_name_bytes, sizeof(odd_name_bytes));
        QVERIFY(decode(malformed).rescan_required);
        malformed = valid;
        const DWORD beyond_buffer = static_cast<DWORD>(valid.size() + 4);
        std::memcpy(malformed.data(), &beyond_buffer, sizeof(beyond_buffer));
        QVERIFY(decode(malformed).rescan_required);
        QList<Windows_extended_record> storm;
        for (int index = 0; index < 300; ++index) {
            storm.append({FILE_ACTION_ADDED, QStringLiteral("file-%1").arg(index), FILE_ATTRIBUTE_NORMAL});
        }
        const auto bounded = decode(windows_extended_records(storm));
        QCOMPARE(bounded.events.size(), 256);
        QVERIFY(bounded.rescan_required);
    }

    void windows_native_entry_types_preserve_file_detail_data()
    {
        QTest::addColumn<quint32>("extended_error");
        QTest::newRow("native-capability") << quint32(ERROR_SUCCESS);
        QTest::newRow("unsupported-function") << quint32(ERROR_INVALID_FUNCTION);
        QTest::newRow("unsupported-filesystem") << quint32(ERROR_NOT_SUPPORTED);
    }

    void windows_native_entry_types_preserve_file_detail()
    {
        QFETCH(quint32, extended_error);
        namespace hooks = vnm::filesystem_observation::detail::native_test_hooks;
        hooks::windows_extended_read_error.store(extended_error);
        const auto reset_fault = qScopeGuard([] { hooks::windows_extended_read_error.store(ERROR_SUCCESS); });
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const bool require_typed = extended_error == ERROR_SUCCESS &&
            local_extended_notifications_supported(workspace.path());
        std::optional<bool> typed;
        qInfo() << "Windows local NTFS extended capability required" << require_typed;
        Native_capture capture;
        Native_watcher watcher([&](const Native_batch& batch) { capture.receive(batch); },
            Watch_mode::RECURSIVE);
        watcher.set_directories({workspace.path()});
        QTRY_VERIFY_WITH_TIMEOUT(watcher.covers_directory(workspace.path()), 5000);
        const auto observed = [&](const QString& path, Event_kind kind, bool directory) {
            return capture.wait_for([&](const QList<Native_batch>& batches) {
                for (const auto& batch : batches) {
                    for (const auto& event : batch.events) {
                        if (event.path != path || event.kind != kind) {
                            continue;
                        }
                        if (!typed.has_value()) {
                            typed = event.entry_type != Entry_type::UNKNOWN;
                        }
                        if ((require_typed && !*typed) ||
                            (extended_error != ERROR_SUCCESS && *typed))
                        {
                            return false;
                        }
                        const Entry_type expected = *typed
                            ? (directory ? Entry_type::DIRECTORY : Entry_type::NON_DIRECTORY)
                            : Entry_type::UNKNOWN;
                        const bool incomplete_rename = event.kind == Event_kind::RENAMED &&
                            event.old_path.isEmpty();
                        return event.entry_type == expected &&
                            batch.rescan_required == (directory || !*typed || incomplete_rename);
                    }
                }
                return false;
            });
        };
        const QString file = workspace.filePath(QStringLiteral("ordinary.txt"));
        const QString renamed_file = workspace.filePath(QStringLiteral("renamed.txt"));
        QVERIFY(write_file(file));
        QVERIFY(observed(file, Event_kind::CREATED, false));
        QVERIFY(QFile::rename(file, renamed_file));
        QVERIFY(observed(renamed_file, Event_kind::RENAMED, false));
        QVERIFY(QFile::remove(renamed_file));
        QVERIFY(observed(renamed_file, Event_kind::REMOVED, false));
        const QString directory = workspace.filePath(QStringLiteral("directory"));
        const QString renamed_directory = workspace.filePath(QStringLiteral("renamed-directory"));
        QVERIFY(QDir().mkdir(directory));
        QVERIFY(observed(directory, Event_kind::CREATED, true));
        QVERIFY(QDir().rename(directory, renamed_directory));
        QVERIFY(observed(renamed_directory, Event_kind::RENAMED, true));
        QVERIFY(QDir().rmdir(renamed_directory));
        QVERIFY(observed(renamed_directory, Event_kind::REMOVED, true));
    }

    void windows_extended_access_failure_does_not_fall_back()
    {
        if (!GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadDirectoryChangesExW")) {
            QSKIP("The runtime does not expose extended notifications");
        }
        namespace detail = vnm::filesystem_observation::detail;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        detail::native_test_hooks::windows_extended_read_error.store(ERROR_ACCESS_DENIED);
        const auto reset_fault = qScopeGuard([] {
            detail::native_test_hooks::windows_extended_read_error.store(ERROR_SUCCESS);
        });
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY(!backend.arm(1, directory.path(), error));
        QVERIFY(error.contains(QString::number(ERROR_ACCESS_DENIED)));
        QCOMPARE(backend.allocated_registrations(), size_t(0));
    }

    void windows_directory_identity_snapshot_does_not_retain_handles_data()
    {
        QTest::addColumn<quint32>("identity_error");
        QTest::newRow("native-identity") << quint32(ERROR_SUCCESS);
        QTest::newRow("unsupported-identity") << quint32(ERROR_NOT_SUPPORTED);
        QTest::newRow("unsupported-identity-parameter") << quint32(ERROR_INVALID_PARAMETER);
    }

    void windows_directory_identity_snapshot_does_not_retain_handles()
    {
        QFETCH(quint32, identity_error);
        namespace detail = vnm::filesystem_observation::detail;
        detail::native_test_hooks::windows_file_id_error.store(identity_error);
        const auto reset_fault = qScopeGuard([] {
            detail::native_test_hooks::windows_file_id_error.store(ERROR_SUCCESS);
        });
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString root = workspace.filePath(QStringLiteral("root"));
        const QString child = QDir(root).filePath(QStringLiteral("child"));
        const QString moved = workspace.filePath(QStringLiteral("moved"));
        QVERIFY(QDir().mkpath(child));
        detail::windows_directory_identity_t before;
        QString final_path;
        QString error;
        QVERIFY2(detail::capture_windows_directory_identity(child, before, final_path, error),
            qPrintable(error));
        QCOMPARE(final_path, child);
        if (identity_error != ERROR_SUCCESS) {
            QVERIFY(!before.extended);
        }
        // A retained child handle would make this one parent rename fail.
        QVERIFY(QDir().rename(root, moved));
        detail::windows_directory_identity_t after;
        QVERIFY2(detail::capture_windows_directory_identity(
            QDir(moved).filePath(QStringLiteral("child")), after, final_path, error), qPrintable(error));
        QCOMPARE(final_path, QDir(moved).filePath(QStringLiteral("child")));
        QVERIFY(detail::same_windows_directory_identity(before, after));
        QVERIFY(QDir().mkpath(child));
        detail::windows_directory_identity_t replacement;
        QVERIFY2(detail::capture_windows_directory_identity(child, replacement, final_path, error),
            qPrintable(error));
        QVERIFY(!detail::same_windows_directory_identity(before, replacement));

        detail::native_test_hooks::windows_file_id_error.store(ERROR_ACCESS_DENIED);
        const auto retained_identity = replacement;
        const QString retained_path = final_path;
        QVERIFY(!detail::capture_windows_directory_identity(child, replacement, final_path, error));
        QVERIFY(error.contains(QString::number(ERROR_ACCESS_DENIED)));
        QVERIFY(detail::same_windows_directory_identity(retained_identity, replacement));
        QCOMPARE(final_path, retained_path);
    }

    void windows_covered_parents_reuse_admitted_identity()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        constexpr int k_roots = 10;
        QList<Watch_spec> paths;
        for (int index = 0; index != k_roots; ++index) {
            const auto path = workspace.filePath(QStringLiteral("repository-%1").arg(index));
            QVERIFY(QDir().mkpath(path));
            paths.append({path, 0});
        }
        detail::Direct_registry registry;
        const auto client = registry.attach([](const Native_batch&) {});
        const auto release = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, paths, Watch_mode::DIRECT,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        const auto all_covered = [&] {
            return std::all_of(paths.cbegin(), paths.cend(), [&](const auto& path) {
                return registry.covers(client, path.path);
            });
        };
        QTRY_VERIFY_WITH_TIMEOUT(all_covered(), 5000);
        const auto probes      = hooks::windows_parent_metadata_probes.load();
        const auto validations = hooks::windows_identity_validations.load();
        // Two boundary-validation rounds cover every explicit root and their
        // shared parent. Reusing a guard must not suppress these identity checks.
        QTRY_VERIFY_WITH_TIMEOUT(
            hooks::windows_identity_validations.load() >= validations + 2 * (k_roots + 1), 5000);
        const auto repeated_probes = hooks::windows_parent_metadata_probes.load() - probes;
        qInfo() << "Covered parent workload:" << k_roots << "roots,"
                << hooks::windows_identity_validations.load() - validations
                << "boundary validations," << repeated_probes << "parent metadata probes";
        QCOMPARE(repeated_probes, uint64_t(0));
        QVERIFY(all_covered());
    }

    void windows_missing_parent_retries_then_recovers_replacement()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto parent = workspace.filePath(QStringLiteral("parent"));
        const auto root   = parent + QStringLiteral("/repository");
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto release = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, {{root, 0}}, Watch_mode::DIRECT,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(!registry.covers(client, root));
        const auto probes = hooks::windows_parent_metadata_probes.load();
        QTRY_VERIFY_WITH_TIMEOUT(hooks::windows_parent_metadata_probes.load() > probes, 5000);

        QVERIFY(QDir().mkpath(root));
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        const auto revision = registry.revision(client, root);
        QVERIFY(QDir().rename(parent, workspace.filePath(QStringLiteral("retired-parent"))));
        QVERIFY(QDir().mkpath(root));
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root) &&
            registry.revision(client, root) > revision, 5000);
        const auto changed = root + QStringLiteral("/after-parent-replacement.txt");
        QVERIFY(write_file(changed));
        QVERIFY(capture.wait_for([&](const auto& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const auto& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const auto& event) {
                    return event.path == changed;
                });
            });
        }));
    }

    void windows_unchanged_observation_does_not_reconcile()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("observed"));
        constexpr int k_directories = 128;
        for (int index = 0; index != k_directories; ++index) {
            QVERIFY(QDir().mkpath(root + QStringLiteral("/directory-%1").arg(index)));
        }
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto release = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        const auto revision = registry.revision(client, root);
        const auto validations = hooks::windows_identity_validations.load();
        const auto descendant_validations = hooks::windows_descendant_identity_validations.load();
        const auto searches = hooks::windows_ancestor_searches.load();
        const auto directories = registry.resource_counts().logical_directories;
        QVERIFY(directories >= k_directories);
        // Boundary validation must progress while unchanged descendants retain
        // the identity protected by their continuous recursive native coverage.
        QTRY_VERIFY_WITH_TIMEOUT(hooks::windows_identity_validations.load() >= validations + 2, 5000);
        QCOMPARE(hooks::windows_descendant_identity_validations.load(), descendant_validations);
        QCOMPARE(hooks::windows_ancestor_searches.load(), searches);

        const auto turns = hooks::reconciliation_turns.load();
        const auto next_validations = hooks::windows_identity_validations.load();
        const auto notifications = hooks::native_notifications.load();
        const auto route_visits = hooks::windows_route_entry_visits.load();
        // The shared ancestor observes this sibling, but no watched root does.
        // Route its native event without restarting completed repository work.
        QVERIFY(write_file(workspace.filePath(QStringLiteral("outside-interest.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(hooks::native_notifications.load() > notifications, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(
            hooks::windows_identity_validations.load() >= next_validations + 2, 5000);
        QCOMPARE(hooks::windows_descendant_identity_validations.load(), descendant_validations);
        QCOMPARE(hooks::reconciliation_turns.load(), turns);
        // An unrelated sibling can match the parent guard, but must not visit
        // the watched descendant inventory just to discard its file detail.
        QVERIFY(hooks::windows_route_entry_visits.load() - route_visits < uint64_t(directories));
        QCOMPARE(registry.revision(client, root), revision);
        QVERIFY(registry.covers(client, root));
        const auto changed = root + QStringLiteral("/directory-0/after-validation.txt");
        QVERIFY(write_file(changed));
        QVERIFY(capture.wait_for([&](const auto& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const auto& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const auto& event) {
                    return event.path == changed;
                });
            });
        }));

        const auto replaced = root + QStringLiteral("/directory-0");
        const auto nested = replaced + QStringLiteral("/replacement-child");
        QVERIFY(QDir().rename(replaced, workspace.filePath(QStringLiteral("retired-directory"))));
        QVERIFY(QDir().mkpath(nested));
        QTRY_VERIFY_WITH_TIMEOUT(registry.covered_logical_directories_for_tests().contains(nested), 5000);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        QVERIFY(hooks::windows_descendant_identity_validations.load() > descendant_validations);
        const auto replacement_file = nested + QStringLiteral("/after-replacement.txt");
        QVERIFY(write_file(replacement_file));
        QVERIFY(capture.wait_for([&](const auto& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const auto& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const auto& event) {
                    return event.path == replacement_file;
                });
            });
        }));
    }

    void windows_identity_captured_before_native_coverage_is_rechecked()
    {
        namespace hooks = detail::native_test_hooks;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("observed"));
        const auto child = root + QStringLiteral("/child");
        const auto replacement = child + QStringLiteral("/replacement");
        QVERIFY(QDir().mkpath(child));
        Native_capture capture;
        detail::Direct_registry registry;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto release = qScopeGuard([&] {
            hooks::windows_pause_uncovered_identity_requested.store(false);
            hooks::windows_uncovered_identity_pause_released.store(true);
            registry.detach(client);
        });
        hooks::windows_uncovered_identity_pause_reached.store(false);
        hooks::windows_uncovered_identity_pause_released.store(false);
        hooks::windows_pause_uncovered_identity_requested.store(true);
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, false);
        QTRY_VERIFY_WITH_TIMEOUT(hooks::windows_uncovered_identity_pause_reached.load(), 5000);
        // The old identity has been captured, but no registration can report
        // this replacement. Arming later cannot repair that historical gap.
        QVERIFY(QDir().rename(child, workspace.filePath(QStringLiteral("retired"))));
        QVERIFY(QDir().mkpath(replacement));
        hooks::windows_uncovered_identity_pause_released.store(true);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        QVERIFY(registry.covered_logical_directories_for_tests().contains(replacement));
        QVERIFY(!capture.diagnostics().contains(QStringLiteral("Directory identity changed during expansion")));
        const auto after = replacement + QStringLiteral("/after-recovery.txt");
        QVERIFY(write_file(after));
        QVERIFY(capture.wait_for([&](const auto& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const auto& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const auto& event) {
                    return event.path == after;
                });
            });
        }));
    }

    void windows_recursive_anchor_preserves_populated_directory_rename_data()
    {
        QTest::addColumn<bool>("force_basic");
        QTest::newRow("native-capability") << false;
        QTest::newRow("basic-fallback") << true;
    }

    void windows_recursive_anchor_preserves_populated_directory_rename()
    {
        // The physical anchor must observe nested changes without retaining a
        // descendant handle that prevents the user's directory rename.
        QFETCH(bool, force_basic);
        namespace detail = vnm::filesystem_observation::detail;
        detail::native_test_hooks::windows_extended_read_error.store(
            force_basic ? ERROR_NOT_SUPPORTED : ERROR_SUCCESS);
        const auto reset_fault = qScopeGuard([] {
            detail::native_test_hooks::windows_extended_read_error.store(ERROR_SUCCESS);
        });
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const QString anchor = workspace.filePath(QStringLiteral("anchor"));
        const QString original = QDir(anchor).filePath(QStringLiteral("original"));
        const QString moved = QDir(anchor).filePath(QStringLiteral("moved"));
        QVERIFY(QDir().mkpath(QDir(original).filePath(QStringLiteral("nested/deeper"))));
        QVERIFY(write_file(QDir(original).filePath(QStringLiteral("nested/deeper/tracked.txt"))));
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, anchor, error), qPrintable(error));
        QCOMPARE(backend.allocated_registrations(), size_t(1));
        const size_t allocated_bytes = backend.allocated_bytes();
        QVERIFY(backend.identity_matches(1));
        QVERIFY(QDir().rename(original, moved));
        bool old_endpoint = false;
        bool new_endpoint = false;
        const auto rename_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while ((!old_endpoint || !new_endpoint) && std::chrono::steady_clock::now() < rename_deadline) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                QVERIFY(!change.coverage_lost);
                for (const auto& event : change.batch.events) {
                    if (event.kind == Event_kind::RENAMED) {
                        old_endpoint |= event.old_path == original;
                        new_endpoint |= event.path == moved;
                    }
                }
            }
        }
        QVERIFY(old_endpoint);
        QVERIFY(new_endpoint);
        QVERIFY(backend.identity_matches(1));
        const QString edited = QDir(moved).filePath(QStringLiteral("nested/deeper/tracked.txt"));
        QVERIFY(write_file(edited, "after directory rename\n"));
        bool observed_edit = false;
        const auto edit_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!observed_edit && std::chrono::steady_clock::now() < edit_deadline) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                QVERIFY(!change.coverage_lost);
                for (const auto& event : change.batch.events) {
                    if (event.path == edited && event.kind == Event_kind::MODIFIED) {
                        observed_edit = true;
                        if (force_basic) {
                            QCOMPARE(event.entry_type, Entry_type::UNKNOWN);
                        }
                    }
                }
            }
        }
        QVERIFY(observed_edit);
        QCOMPARE(backend.allocated_registrations(), size_t(1));
        QCOMPARE(backend.allocated_bytes(), allocated_bytes);
        backend.retire(1);
        QCOMPARE(backend.allocated_registrations(), size_t(1));
        QVERIFY(backend.wait(std::chrono::seconds(5)).changes.isEmpty());
        QCOMPARE(backend.allocated_registrations(), size_t(0));
        QCOMPARE(backend.allocated_bytes(), size_t(0));
    }

    void windows_overflow_retains_registration_data()
    {
        QTest::addColumn<bool>("zero_detail");
        QTest::addColumn<bool>("reject_rearm");
        QTest::newRow("zero-detail")           << true  << false;
        QTest::newRow("notify-enum-dir")       << false << false;
        QTest::newRow("failed-overflow-rearm") << true  << true;
    }

    void windows_overflow_retains_registration()
    {
        QFETCH(bool, zero_detail);
        QFETCH(bool, reject_rearm);
        namespace detail = vnm::filesystem_observation::detail;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        if (reject_rearm && !local_extended_notifications_supported(directory.path())) {
            QSKIP("Rearm failure injection requires extended notifications");
        }
        detail::Direct_native_backend backend;
        QString error;
        QVERIFY2(backend.arm(1, directory.path(), error), qPrintable(error));
        const auto bytes = backend.allocated_bytes();
        const auto reset_faults = qScopeGuard([] {
            detail::native_test_hooks::windows_zero_detail_completion.store(false);
            detail::native_test_hooks::windows_completion_error.store(ERROR_SUCCESS);
            detail::native_test_hooks::windows_extended_read_error.store(ERROR_SUCCESS);
        });
        if (zero_detail) {
            detail::native_test_hooks::windows_zero_detail_completion.store(true);
        }
        else {
            detail::native_test_hooks::windows_completion_error.store(ERROR_NOTIFY_ENUM_DIR);
        }
        if (reject_rearm) {
            detail::native_test_hooks::windows_extended_read_error.store(ERROR_ACCESS_DENIED);
        }
        QVERIFY(write_file(directory.filePath(QStringLiteral("overflow-trigger.txt"))));
        const auto changes = backend.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(changes.size(), 1);
        const auto& change = changes[0];
        QVERIFY(change.batch.rescan_required);
        QVERIFY(!change.batch.rescan_event_paths_complete);
        QVERIFY(!change.batch.consumer_reconciliation_only);
        QCOMPARE(change.coverage_lost, reject_rearm);
        QCOMPARE(backend.loss_counts().kernel_overflows, uint64_t(1));
        QCOMPARE(backend.loss_counts().decoder_budget_losses, uint64_t(0));
        if (reject_rearm) {
            QCOMPARE(change.batch.reason, Native_reason::REGISTRATION_FAILED);
            QVERIFY(change.batch.diagnostic.startsWith(QStringLiteral("Directory notification rearm")));
            QVERIFY(change.batch.diagnostic.contains(QString::number(ERROR_ACCESS_DENIED)));
            QCOMPARE(backend.allocated_registrations(), size_t(0));
            return;
        }
        QCOMPARE(change.batch.reason, Native_reason::QUEUE_OVERFLOW);
        QCOMPARE(backend.allocated_registrations(), size_t(1));
        QCOMPARE(backend.allocated_bytes(), bytes);
        QVERIFY(backend.identity_matches(1));
        const auto after = directory.filePath(QStringLiteral("after-overflow.txt"));
        QVERIFY(write_file(after));
        bool observed = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!observed && std::chrono::steady_clock::now() < deadline) {
            for (const auto& next : backend.wait(std::chrono::milliseconds(100)).changes) {
                QVERIFY(!next.coverage_lost);
                for (const auto& event : next.batch.events) {
                    observed |= event.path == after;
                }
            }
        }
        QVERIFY(observed);
    }

    void windows_overflow_preserves_in_flight_expansion_data()
    {
        QTest::addColumn<bool>("replace_anchor");
        QTest::newRow("notification-overflow") << false;
        QTest::newRow("anchor-replacement") << true;
    }

    void windows_overflow_preserves_in_flight_expansion()
    {
        // Neither a second overflow nor a new ancestor anchor lets the held
        // scan satisfy the fresh enumeration needed by the current coverage.
        QFETCH(bool, replace_anchor);
        namespace detail = vnm::filesystem_observation::detail;
        using Stage = Native_watcher::Expansion_stage;
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto parent = workspace.filePath(QStringLiteral("parent"));
        const auto root   = parent + QStringLiteral("/root");
        QVERIFY(QDir().mkpath(root));
        detail::Direct_registry registry;
        Native_capture capture;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto ancestor = registry.attach([](const Native_batch&) {});
        QSemaphore paused;
        QSemaphore fresh_scan;
        QSemaphore resume;
        std::atomic_int results = 0;
        std::atomic_bool timed_out = false;
        const auto release = qScopeGuard([&] {
            resume.release(2);
            registry.detach(client);
            registry.detach(ancestor);
        });
        registry.replace(client, {{root, 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        QVERIFY(registry.covers(client, root));
        const auto before = registry.resource_counts();
        registry.set_expansion_observer_for_tests(client, [&](Stage stage) {
            if (stage == Stage::BEFORE_RESULT) {
                const auto result = results.fetch_add(1);
                if (result >= 2) {
                    return;
                }
                (result == 0 ? paused : fresh_scan).release();
                if (!resume.tryAcquire(1, 10000)) {
                    timed_out.store(true);
                }
            }
        });
        registry.inject_overflow_for_tests(client);
        QVERIFY(paused.tryAcquire(1, 5000));
        const auto count = capture.count();
        if (replace_anchor) {
            registry.replace(ancestor, {{parent, 0}}, Watch_mode::DIRECT,
                std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
            QVERIFY(registry.armed_directories_for_tests().contains(workspace.path()));
        }
        else {
            registry.inject_overflow_for_tests(client);
            QVERIFY(capture.wait_for([&](const QList<Native_batch>& batches) {
                return std::any_of(batches.cbegin() + count, batches.cend(), [](const Native_batch& batch) {
                    return batch.reason == Native_reason::QUEUE_OVERFLOW && batch.rescan_required &&
                        !batch.consumer_reconciliation_only;
                });
            }));
            QCOMPARE(registry.resource_counts().logical_directories, before.logical_directories);
            QCOMPARE(registry.resource_counts().armed, before.armed);
        }
        const auto pending = registry.coverage_status(client, root);
        QCOMPARE(pending.state, Coverage_state::PENDING);
        QVERIFY(pending.diagnostic.isEmpty());
        const auto expansions = registry.expansion_count_for_tests(client);
        resume.release();
        QVERIFY(fresh_scan.tryAcquire(1, 5000));
        QVERIFY(!registry.covers(client, root));
        QCOMPARE(registry.coverage_status(client, root).state, Coverage_state::PENDING);
        QCOMPARE(registry.expansion_count_for_tests(client), expansions + (replace_anchor ? 0 : 1));
        resume.release();
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root), 5000);
        QCOMPARE(registry.expansion_count_for_tests(client), expansions + (replace_anchor ? 1 : 2));
        QVERIFY(!capture.diagnostics().contains(QStringLiteral("Directory identity changed during expansion")));
        QCOMPARE(registry.coverage_status(client, root).state, Coverage_state::COVERED);
        QVERIFY(!timed_out.load());
    }

    void windows_removed_descendant_preserves_parent_coverage_during_readback()
    {
        QTemporaryDir workspace;
        QVERIFY(workspace.isValid());
        const auto root = workspace.filePath(QStringLiteral("root"));
        const auto child = root + QStringLiteral("/child");
        const auto leaf = child + QStringLiteral("/leaf");
        const auto trigger = child + QStringLiteral("/readback-trigger");
        const auto surviving_file = root + QStringLiteral("/surviving.txt");
        QVERIFY(QDir().mkpath(leaf));
        QVERIFY(write_file(leaf + QStringLiteral("/tracked.txt")));
        QVERIFY(write_file(surviving_file));

        Native_capture parent_capture;
        Native_capture child_capture;
        std::atomic_uint64_t admitted_revision = 0;
        std::atomic_bool parent_failed = false;
        std::atomic_bool coverage_changed = false;
        QSemaphore paused;
        QSemaphore resume;
        std::atomic_bool pause_once = true;
        std::atomic_bool timed_out = false;
        detail::Direct_registry registry;
        const auto parent_client = registry.attach([&](const Native_batch& batch) {
            if (const auto revision = admitted_revision.load(); revision != 0) {
                if (batch.reason == Native_reason::REGISTRATION_FAILED) {
                    parent_failed.store(true);
                }
                if (batch.coverage_revision != revision) {
                    coverage_changed.store(true);
                }
            }
            parent_capture.receive(batch);
        });
        const auto child_client = registry.attach([&](const Native_batch& batch) { child_capture.receive(batch); });
        const auto release = qScopeGuard([&] {
            resume.release();
            registry.detach(parent_client);
            registry.detach(child_client);
        });
        const auto policy = std::make_shared<vnm::path_name::Policy_epoch>();
        registry.replace(parent_client, {{root, 0}}, Watch_mode::RECURSIVE, policy, {}, true);
        registry.replace(child_client, {{child, 0}}, Watch_mode::RECURSIVE, policy, {}, true);
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().scan_jobs, size_t(0), 5000);
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().scan_pending, 0, 5000);
        QCOMPARE(registry.coverage_status(parent_client, root).state, Coverage_state::COVERED);
        QCOMPARE(registry.coverage_status(child_client, child).state, Coverage_state::COVERED);
        QVERIFY(registry.covered_logical_directories_for_tests().contains(leaf));
        const auto revision = registry.revision(parent_client, root);
        admitted_revision.store(revision);

        // Only the admitted child has new topology, so its enumeration owns the
        // held result. Removing it must retire that result along with its subtree.
        registry.set_expansion_observer_for_tests(parent_client, [&](Native_watcher::Expansion_stage stage) {
            if (stage == Native_watcher::Expansion_stage::BEFORE_RESULT && pause_once.exchange(false)) {
                paused.release();
                if (!resume.tryAcquire(1, 10000)) {
                    timed_out.store(true);
                }
            }
        });
        QVERIFY(QDir().mkdir(trigger));
        QVERIFY(paused.tryAcquire(1, 5000));
        QCOMPARE(registry.coverage_status(parent_client, root).state, Coverage_state::COVERED);
        QVERIFY(QDir(child).removeRecursively());
        QVERIFY(parent_capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [&](const Native_batch& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                    return event.path == child && event.kind == Event_kind::REMOVED;
                });
            });
        }));
        QVERIFY(child_capture.wait_for([](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin(), batches.cend(), [](const Native_batch& batch) {
                return batch.reason == Native_reason::REGISTRATION_FAILED;
            });
        }));
        const auto child_status = registry.coverage_status(child_client, child);
        QCOMPARE(child_status.state, Coverage_state::FAILED);
        QVERIFY(!child_status.diagnostic.isEmpty());
        QCOMPARE(registry.coverage_status(parent_client, root).state, Coverage_state::COVERED);
        QCOMPARE(registry.revision(parent_client, root), revision);
        QVERIFY(!parent_failed.load());
        QVERIFY(!coverage_changed.load());

        resume.release();
        QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().scan_jobs, size_t(0), 5000);
        const auto covered = registry.covered_logical_directories_for_tests();
        QVERIFY(!covered.contains(child));
        QVERIFY(!covered.contains(leaf));
        QVERIFY(!covered.contains(trigger));
        const auto delivered = parent_capture.count();
        QVERIFY(write_file(surviving_file, "after subtree removal\n"));
        QVERIFY(parent_capture.wait_for([&](const QList<Native_batch>& batches) {
            return std::any_of(batches.cbegin() + delivered, batches.cend(), [&](const Native_batch& batch) {
                return std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                    return event.path == surviving_file && event.kind == Event_kind::MODIFIED;
                });
            });
        }));
        QCOMPARE(registry.coverage_status(parent_client, root).state, Coverage_state::COVERED);
        QCOMPARE(registry.revision(parent_client, root), revision);
        QCOMPARE(registry.coverage_status(child_client, child).state, Coverage_state::FAILED);
        QVERIFY(!parent_failed.load());
        QVERIFY(!coverage_changed.load());
        QVERIFY(!timed_out.load());
    }

    void windows_expansion_identity_query_reports_native_failure()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        detail::Direct_registry registry;
        Native_capture capture;
        const auto client = registry.attach([&](const Native_batch& batch) { capture.receive(batch); });
        const auto release = qScopeGuard([&] {
            detail::native_test_hooks::windows_file_id_error.store(ERROR_SUCCESS);
            registry.detach(client);
        });
        std::atomic_bool injected = false;
        registry.set_expansion_observer_for_tests(client, [&](Native_watcher::Expansion_stage stage) {
            if (stage == Native_watcher::Expansion_stage::BEFORE_RESULT && !injected.exchange(true)) {
                detail::native_test_hooks::windows_file_id_error.store(ERROR_ACCESS_DENIED);
            }
        });
        registry.replace(client, {{directory.path(), 0}}, Watch_mode::RECURSIVE,
            std::make_shared<vnm::path_name::Policy_epoch>(), {}, true);
        const auto failure = registry.coverage_status(client, directory.path());
        QCOMPARE(failure.state, Coverage_state::FAILED);
        QCOMPARE(failure.diagnostic, QStringLiteral("Directory identity failed (Windows error 5)"));
        QVERIFY(!capture.diagnostics().contains(QStringLiteral("Directory identity changed during expansion")));
        detail::native_test_hooks::windows_file_id_error.store(ERROR_SUCCESS);
        QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, directory.path()), 5000);
        QCOMPARE(registry.coverage_status(client, directory.path()).state, Coverage_state::COVERED);
    }

    void windows_extended_async_unsupported_reconciles_before_basic_detail_data()
    {
        QTest::addColumn<quint32>("completion_error");
        QTest::addColumn<bool>("reject_rearm");
        QTest::newRow("async-unsupported-function") << quint32(ERROR_INVALID_FUNCTION) << false;
        QTest::newRow("async-unsupported-filesystem") << quint32(ERROR_NOT_SUPPORTED) << false;
        QTest::newRow("rearm-unsupported-function") << quint32(ERROR_INVALID_FUNCTION) << true;
        QTest::newRow("rearm-unsupported-filesystem") << quint32(ERROR_NOT_SUPPORTED) << true;
    }

    void windows_extended_async_unsupported_reconciles_before_basic_detail()
    {
        QFETCH(quint32, completion_error);
        QFETCH(bool, reject_rearm);
        namespace detail = vnm::filesystem_observation::detail;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        if (!local_extended_notifications_supported(directory.path())) {
            QSKIP("This filesystem does not provide extended notifications");
        }
        detail::Direct_native_drain backend;
        QString error;
        QVERIFY2(backend.arm(1, directory.path(), error), qPrintable(error));
        if (reject_rearm) {
            detail::native_test_hooks::windows_extended_read_error.store(completion_error);
        }
        else {
            detail::native_test_hooks::windows_completion_error.store(completion_error);
        }
        const auto reset_fault = qScopeGuard([] {
            detail::native_test_hooks::windows_completion_error.store(ERROR_SUCCESS);
            detail::native_test_hooks::windows_extended_read_error.store(ERROR_SUCCESS);
        });
        QVERIFY(write_file(directory.filePath(QStringLiteral("before-fallback.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(backend.resource_counts().batches > 0, 5000);
        const auto lost_detail = backend.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(lost_detail.size(), 1);
        QVERIFY(lost_detail[0].batch.rescan_required);
        QVERIFY(!lost_detail[0].coverage_lost);
        QCOMPARE(backend.allocated_registrations(), size_t(1));
        const QString after = directory.filePath(QStringLiteral("after-fallback.txt"));
        QVERIFY(write_file(after));
        bool observed = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!observed && std::chrono::steady_clock::now() < deadline) {
            for (const auto& change : backend.wait(std::chrono::milliseconds(100)).changes) {
                for (const auto& event : change.batch.events) {
                    if (event.path == after) {
                        QCOMPARE(event.entry_type, Entry_type::UNKNOWN);
                        observed = true;
                    }
                }
            }
        }
        QVERIFY(observed);
    }

    void windows_extended_fallback_reopen_failure_loses_coverage()
    {
        namespace detail = vnm::filesystem_observation::detail;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        if (!local_extended_notifications_supported(directory.path())) {
            QSKIP("This filesystem does not provide extended notifications");
        }
        detail::Direct_native_drain backend;
        QString error;
        QVERIFY2(backend.arm(1, directory.path(), error), qPrintable(error));
        detail::native_test_hooks::windows_completion_error.store(ERROR_NOT_SUPPORTED);
        detail::native_test_hooks::windows_open_error.store(ERROR_ACCESS_DENIED);
        const auto reset_faults = qScopeGuard([] {
            detail::native_test_hooks::windows_completion_error.store(ERROR_SUCCESS);
            detail::native_test_hooks::windows_open_error.store(ERROR_SUCCESS);
        });
        QVERIFY(write_file(directory.filePath(QStringLiteral("fallback-trigger.txt"))));
        QTRY_VERIFY_WITH_TIMEOUT(backend.resource_counts().batches > 0, 5000);
        const auto changes = backend.wait(std::chrono::seconds(5)).changes;
        QCOMPARE(changes.size(), 1);
        QVERIFY(changes[0].batch.rescan_required);
        QVERIFY(changes[0].coverage_lost);
        QCOMPARE(changes[0].batch.reason, Native_reason::REGISTRATION_FAILED);
        QVERIFY(changes[0].batch.diagnostic.contains(QString::number(ERROR_ACCESS_DENIED)));
        QCOMPARE(backend.allocated_registrations(), size_t(0));
    }

    void windows_detail_loss_and_rename_decoding()
    {
        // Oracle: FILE_NOTIFY_INFORMATION actions plus the adopted bounded rescan contract.
        const QString root = QStringLiteral("C:/watched");
        const auto paired = Native_watcher::decode_windows_notifications_for_tests(root,
            windows_records({{FILE_ACTION_RENAMED_OLD_NAME, QStringLiteral("before.txt")},
                             {FILE_ACTION_RENAMED_NEW_NAME, QStringLiteral("after.txt")}}));
        QCOMPARE(paired.events.size(), 1);
        QCOMPARE(paired.events[0].old_path, root + QStringLiteral("/before.txt"));
        QCOMPARE(paired.events[0].path, root + QStringLiteral("/after.txt"));
        QVERIFY(!paired.rescan_required);
        const auto partial = Native_watcher::decode_windows_notifications_for_tests(root,
            windows_records({{FILE_ACTION_RENAMED_OLD_NAME, QStringLiteral("before.txt")}}));
        QCOMPARE(partial.events[0].old_path, root + QStringLiteral("/before.txt"));
        QVERIFY(partial.rescan_required);
        QVERIFY(Native_watcher::decode_windows_notifications_for_tests(root, {}).rescan_required);
        QVERIFY(Native_watcher::decode_windows_notifications_for_tests(root,
            QByteArray(3, '\0')).rescan_required);
        QList<std::pair<DWORD, QString>> storm;
        for (int index = 0; index < 300; ++index) {
            storm.append({FILE_ACTION_MODIFIED, QStringLiteral("file-%1.txt").arg(index)});
        }
        const auto bounded = Native_watcher::decode_windows_notifications_for_tests(root,
            windows_records(storm));
        QVERIFY(bounded.events.size() <= 256);
        QVERIFY(bounded.rescan_required);
        QVERIFY(!bounded.diagnostic.isEmpty());
        const auto decode = [&](const QByteArray& bytes) {
            return detail::decode_windows_notifications(root, bytes.constData(), uint32_t(bytes.size()));
        };
        QVERIFY(decode(windows_records(storm)).budget_exceeded);
        QVERIFY(!decode({}).budget_exceeded);
        QVERIFY(!decode(QByteArray(3, '\0')).budget_exceeded);
        QVERIFY(!decode(windows_records({
            {FILE_ACTION_RENAMED_OLD_NAME, QStringLiteral("before.txt")}})).budget_exceeded);
    }
#endif

    void replacement_preserves_monotonic_coverage_revision()
    {
        // Oracle: loss/recovery and replacement must remain distinguishable.
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        Native_watcher watcher([](const Native_batch&) {}, Watch_mode::DIRECT);
        watcher.set_directories({directory.path()});
        QVERIFY(watcher.covers_directory(directory.path()));
        const auto armed = watcher.coverage_revision(directory.path());
        watcher.set_coverage_for_tests(directory.path(), false);
        const auto lost = watcher.coverage_revision(directory.path());
        QVERIFY(lost > armed);
        QCOMPARE(watcher.coverage_status(directory.path()).state, Coverage_state::FAILED);
        QCOMPARE(watcher.coverage_status(directory.path()).diagnostic,
            QStringLiteral("Injected directory coverage loss"));
        watcher.set_coverage_for_tests(directory.path(), true);
        QVERIFY(watcher.coverage_revision(directory.path()) > lost);
        QCOMPARE(watcher.coverage_status(directory.path()).state, Coverage_state::COVERED);
        QVERIFY(watcher.coverage_status(directory.path()).diagnostic.isEmpty());
        const auto recovered = watcher.coverage_revision(directory.path());
        watcher.clear();
        watcher.set_directories({directory.path()});
        QVERIFY(watcher.coverage_revision(directory.path()) > recovered);
    }
};

QTEST_GUILESS_MAIN(Native_watcher_tests)
#include "vnm_filesystem_native_watcher_tests.moc"
