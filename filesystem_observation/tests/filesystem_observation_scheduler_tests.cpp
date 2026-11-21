#include "vnm_filesystem_observation.h"
#include "vnm_filesystem_observation_qt.h"
#include "vnm_native_test_hooks_p.h"
#ifdef Q_OS_WIN
#include "vnm_direct_registry_p.h"
#elif defined(Q_OS_MACOS)
#include "vnm_direct_native_backend_p.h"
#endif

#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTemporaryDir>
#include <QScopeGuard>
#include <QSemaphore>
#include <QtTest>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <future>
#include <latch>
#include <optional>
#include <thread>
#include <stdexcept>

namespace observation = vnm::filesystem_observation;
using namespace std::chrono_literals;

namespace {

observation::Native_batch change(const QString& path)
{
    observation::Native_batch batch;
    batch.root = QStringLiteral("/observed");
    batch.scope = batch.root;
    batch.events.append({path, {}, observation::Event_kind::MODIFIED});
    return batch;
}

bool wait_until(const std::function<bool()>& predicate)
{
    const auto end = std::chrono::steady_clock::now() + 3s;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= end) {
            return false;
        }
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

#ifdef Q_OS_MACOS
bool complete_native_fixture_setup(const QString& directory)
{
    observation::detail::Direct_native_backend witness;
    QString error;
    if (!witness.arm(1, directory, error)) {
        qWarning().noquote() << "Native fixture witness could not arm:" << error;
        return false;
    }
    // FSEvents can assign setup mutations their IDs after an arm cutoff. Seeing
    // a later marker establishes that native setup traffic precedes subscription.
    const auto marker = directory + QStringLiteral("/native-setup-ready");
    if (!QDir().mkdir(marker)) {
        return false;
    }
    // Keep the marker until the enclosing temporary directory is removed, after
    // the service, so its deletion cannot introduce traffic into the assertion.
    return wait_until([&] {
        for (const auto& change : witness.wait(20ms).changes) {
            for (const auto& event : change.batch.events) {
                if (event.path == marker) {
                    return true;
                }
            }
        }
        return false;
    });
}
#endif

bool create_directory_alias(const QString& target, const QString& alias)
{
#ifdef Q_OS_WIN
    QProcess process;
    process.start(QStringLiteral("cmd.exe"), {QStringLiteral("/d"), QStringLiteral("/c"),
        QStringLiteral("mklink"), QStringLiteral("/J"),
        QDir::toNativeSeparators(alias), QDir::toNativeSeparators(target)});
    return process.waitForStarted(4000) && process.waitForFinished(4000) &&
        process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
#else
    return QFile::link(target, alias);
#endif
}

bool remove_directory_alias(const QString& alias)
{
#ifdef Q_OS_WIN
    return QDir().rmdir(alias);
#else
    return QFile::remove(alias);
#endif
}

void report_observation_batch(const QString& stage, const observation::Batch* batch)
{
    QJsonObject record{{"stage", stage}, {"delivered", batch != nullptr}};
    if (batch) {
        record.insert("subscription", qint64(batch->capture.subscription_id));
        record.insert("generation", qint64(batch->capture.generation));
        record.insert("event_sequence", qint64(batch->capture.event_sequence));
        record.insert("coverage_sequence", qint64(batch->capture.coverage_sequence));
        record.insert("rescan_required", batch->rescan_required);
        record.insert("all_interests", batch->all_interests);
        record.insert("consumer_reconciliation_only", batch->consumer_reconciliation_only);
        record.insert("initial_admission_only", batch->initial_admission_only);
        record.insert("diagnostic", batch->diagnostic);
        record.insert("scopes", qint64(batch->scopes.size()));
        record.insert("events", qint64(batch->events.size()));
    }
    qInfo().noquote() << QJsonDocument(record).toJson(QJsonDocument::Compact);
    if (!batch) {
        return;
    }
    // Keep each scope/event separate so a batch cannot truncate its own evidence.
    for (const auto& scope : batch->scopes) {
        qInfo().noquote() << QJsonDocument(QJsonObject{
            {"stage", stage}, {"scope", scope}}).toJson(QJsonDocument::Compact);
    }
    for (const auto& event : batch->events) {
        qInfo().noquote() << QJsonDocument(QJsonObject{
            {"stage", stage}, {"path", event.path}, {"old_path", event.old_path},
            {"kind", int(event.kind)}, {"entry_type", int(event.entry_type)}})
            .toJson(QJsonDocument::Compact);
    }
}

void report_observation_state(const QString& stage, const observation::Service& service,
    const observation::Subscription& subscription, const QString& path)
{
    const auto statistics = service.statistics();
    const auto resources  = service.resource_counts();
    const auto coverage   = subscription.coverage_status(path);
    qInfo().noquote() << QJsonDocument(QJsonObject{
        {"stage", stage}, {"path", path},
        {"coverage_state", int(coverage.state)}, {"coverage_diagnostic", coverage.diagnostic},
        {"coverage_revision", qint64(subscription.coverage_revision(path))},
        {"rescan_required", subscription.rescan_required()},
        {"dispatches", qint64(statistics.dispatches)},
        {"retained_events", qint64(statistics.retained_events)},
        {"outstanding", qint64(statistics.outstanding)},
        {"pending_registrations", qint64(statistics.pending_registrations)},
        {"desired", resources.desired}, {"armed", resources.armed},
        {"failed", resources.failed}, {"scan_pending", resources.scan_pending},
        {"scan_failed", resources.scan_failed}, {"retiring", resources.retiring},
        {"scan_jobs", qint64(resources.scan_jobs)},
        {"logical_directories", resources.logical_directories},
        {"covered_logical_directories", resources.covered_logical_directories},
        {"native_batches", qint64(resources.native_batches)},
        {"kernel_overflows", qint64(resources.kernel_overflows)},
        {"decoder_budget_losses", qint64(resources.decoder_budget_losses)},
        {"handoff_overflows", qint64(resources.handoff_overflows)}})
        .toJson(QJsonDocument::Compact);
}

} // namespace

// Oracle: adopted watch_design_adopted.md section 1 fixes all scheduling,
// completion, memory promotion and generation expectations exercised here.
class Filesystem_observation_scheduler_tests : public QObject
{
    Q_OBJECT

private slots:
    void leading_fixed_deadline_trailing_and_quiet();
    void independent_document_interval_and_busy_receiver();
    void interval_update_preserves_established_deadline();
    void bounded_ingress_and_rescan_acknowledgement();
    void rename_endpoints_and_incomplete_detail();
    void partial_rename_reconciles_only_matching_interests();
    void obligation_reason_survives_normal_work();
    void consumer_reconciliation_preserves_real_work_data();
    void consumer_reconciliation_preserves_real_work();
    void admission_provenance_retains_source_causes_data();
    void admission_provenance_retains_source_causes();
    void admission_after_replan_preserves_unacknowledged_source_detail();
    void native_admission_is_local_to_new_subscriber();
    void filter_replan_requires_continuous_coverage_data();
    void filter_replan_requires_continuous_coverage();
    void pending_filter_preserves_reconciliation_cause_data();
    void pending_filter_preserves_reconciliation_cause();
    void pending_filter_delivers_once_and_recovers();
    void retained_descendant_loss_reconciles_pending_filter();
    void injected_unavailability_survives_directory_restoration();
    void detail_during_reconciliation_does_not_extend_obligation();
    void one_shot_acknowledgement_during_classification_data();
    void one_shot_acknowledgement_during_classification();
    void coverage_transition_bypasses_content_classifier();
    void unsubscribe_replacement_and_shutdown();
    void reset_waits_for_running_classifier();
    void classifier_may_reset_its_own_subscription();
#ifdef Q_OS_LINUX
    void reset_retires_directory_filter();
#endif
    void qt_dropped_event_releases_delivery();
    void qt_cancel_serializes_with_receiver_destruction();
    void native_delivery_without_calling_event_loop();
    void duplicate_discovery_roots_preserve_deepest_interest_data();
    void duplicate_discovery_roots_preserve_deepest_interest();
    void native_shared_subscribers_progress_while_one_is_held();
    void direct_overlapping_interests_share_native_owner();
    void recursive_and_direct_interests_share_physical_union();
    void explicit_recursive_alias_reconciles_without_following_descendant_links();
    void sibling_rename_preserves_guarded_and_exact_captures();
#ifdef Q_OS_WIN
    void windows_discovery_settles_with_dangling_descendant_junction();
    void windows_ancestor_keeps_overlapping_interests_movable();
    void windows_disjoint_replacement_releases_obsolete_plan_memory();
    void windows_disjoint_retirement_preserves_healthy_capture();
#endif
    void eligibility_replacement_preserves_capture_and_shared_reasons_data();
    void eligibility_replacement_preserves_capture_and_shared_reasons();
    void unchanged_expansion_failure_retains_coverage_obligation_data();
    void unchanged_expansion_failure_retains_coverage_obligation();
    void direct_sharing_preserves_independent_capture_and_retirement();
    void direct_budget_failure_recovers_after_last_user_retires_data();
    void direct_budget_failure_recovers_after_last_user_retires();
#ifdef Q_OS_LINUX
    void direct_wake_exhaustion_recovers_without_replacing_interest();
#endif
    void late_native_subscriber_receives_its_own_reconciliation_data();
    void late_native_subscriber_receives_its_own_reconciliation();
    void unrelated_groups_do_not_multiply_policy_queries();
    void coverage_reads_do_not_scan_unrelated_interests_data();
    void coverage_reads_do_not_scan_unrelated_interests();
    void combined_directory_and_exact_file_interests();
    void event_descendants_do_not_extend_policy_history();
    void named_policy_forks_preserve_captured_modes();
    void native_path_policy_matches_directory_case_sensitivity();
    void policy_history_retires_with_subscriptions();
    void policy_prefix_budget_rejects_without_source_mutation();
    void uncapped_workload_preserves_native_delivery_and_detail_bounds_data();
    void uncapped_workload_preserves_native_delivery_and_detail_bounds();
    void typed_settings();
};

void Filesystem_observation_scheduler_tests::duplicate_discovery_roots_preserve_deepest_interest_data()
{
    QTest::addColumn<QList<int>>("depths");
    QTest::newRow("shallow-first") << QList<int>{1, 3};
    QTest::newRow("deep-first") << QList<int>{3, 1};
    QTest::newRow("root-only-first") << QList<int>{0, 3};
    QTest::newRow("single-deep-interest") << QList<int>{3};
}

void Filesystem_observation_scheduler_tests::duplicate_discovery_roots_preserve_deepest_interest()
{
    QFETCH(QList<int>, depths);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("root"));
    const auto deep_file = root + QStringLiteral("/a/b/c/document.txt");
    QVERIFY(QDir().mkpath(QFileInfo(deep_file).absolutePath()));

    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DISCOVERY_RECURSIVE;
    options.interval = 1ms;
    for (int depth : depths) {
        options.directories.append({root, depth});
    }
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
    while (auto initial = channel->wait(100ms)) {
        subscription.acknowledge(initial->batch.capture);
    }
    QVERIFY(!subscription.rescan_required());

    QFile file(deep_file);
    QVERIFY(file.open(QIODevice::WriteOnly));
    QCOMPARE(file.write("changed"), qint64(7));
    file.close();
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            subscription.acknowledge(delivery->batch.capture);
            return std::any_of(delivery->batch.events.cbegin(), delivery->batch.events.cend(),
                [&](const auto& event) { return event.path == deep_file; });
        }
        return false;
    }));
}

void Filesystem_observation_scheduler_tests::leading_fixed_deadline_trailing_and_quiet()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/first")));
    auto first = channel->wait(3s);
    QVERIFY(first);
    QCOMPARE(first->batch.events.front().path, QStringLiteral("/observed/first"));
    first.reset();

    service.advance_clock_for_tests(1s);
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/second")));
    service.advance_clock_for_tests(2s);
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/final")));
    QVERIFY(!channel->wait(20ms));
    service.advance_clock_for_tests(1s);
    auto trailing = channel->wait(3s);
    QVERIFY(trailing);
    QCOMPARE(trailing->batch.events.size(), 2);
    trailing.reset();

    service.advance_clock_for_tests(4s);
    QVERIFY(!channel->wait(20ms));
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/after_quiet")));
    auto next_leading = channel->wait(3s);
    QVERIFY(next_leading);
    QCOMPARE(service.statistics().dispatches, uint64_t(3));
}

void Filesystem_observation_scheduler_tests::independent_document_interval_and_busy_receiver()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto general_channel = std::make_shared<observation::Wait_channel>();
    auto document_channel = std::make_shared<observation::Wait_channel>();
    auto general = service.subscribe({}, general_channel);
    observation::Subscription_options options;
    options.interval = observation::Configuration{}.document_interval;
    auto document = service.subscribe(options, document_channel);
    QCOMPARE(general.effective_interval(), 4000ms);
    QCOMPARE(document.effective_interval(), 2000ms);

    service.ingest_for_tests(general, change(QStringLiteral("/observed/a")));
    service.ingest_for_tests(document, change(QStringLiteral("/observed/a")));
    auto held = general_channel->wait(3s);
    auto leading_document = document_channel->wait(3s);
    QVERIFY(held && leading_document);
    leading_document.reset();
    for (int i = 0; i < 4; ++i) {
        const auto path = QStringLiteral("/observed/change-%1").arg(i);
        service.ingest_for_tests(general, change(path));
        service.ingest_for_tests(document, change(path));
        service.advance_clock_for_tests(2s);
        auto delivery = document_channel->wait(3s);
        QVERIFY(delivery);
        QVERIFY(!general_channel->wait(5ms));
    }
    QCOMPARE(service.statistics().outstanding, size_t(1));
    held.reset();
    auto final_union = general_channel->wait(3s);
    QVERIFY(final_union);
    QCOMPARE(final_union->batch.events.size(), 4);
    QCOMPARE(service.statistics().dispatches, uint64_t(7));
}

void Filesystem_observation_scheduler_tests::interval_update_preserves_established_deadline()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/a")));
    auto first = channel->wait(3s);
    QVERIFY(first);
    first.reset();
    subscription.update_interval(2s);
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/b")));
    service.advance_clock_for_tests(2s);
    QVERIFY(!channel->wait(20ms));
    service.advance_clock_for_tests(2s);
    auto second = channel->wait(3s);
    QVERIFY(second);
    second.reset();
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/c")));
    service.advance_clock_for_tests(2s);
    QVERIFY(channel->wait(3s));
}

void Filesystem_observation_scheduler_tests::bounded_ingress_and_rescan_acknowledgement()
{
    observation::limits_t limits;
    limits.retained_events = 4;
    limits.retained_characters = 256;
    observation::Service service(limits);
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    subscription.request_rescan(QStringLiteral("Native enumeration lost detail"));
    auto first = channel->wait(3s);
    QVERIFY(first && first->batch.rescan_required);
    const auto stale_capture = first->batch.capture;
    first.reset();
    QVERIFY(subscription.rescan_required());

    for (int i = 0; i < 500; ++i) {
        service.ingest_for_tests(subscription, change(QStringLiteral("/observed/path-%1").arg(i)));
    }
    QVERIFY(!subscription.acknowledge(stale_capture));
    service.advance_clock_for_tests(4s);
    auto promoted = channel->wait(3s);
    QVERIFY(promoted);
    QVERIFY(promoted->batch.rescan_required);
    QVERIFY(promoted->batch.all_interests);
    QVERIFY(promoted->batch.events.size() <= 4);
    QVERIFY(service.statistics().retained_events <= 8);
    QVERIFY(service.statistics().promotions > 0);
    const auto captured = promoted->batch.capture;

    auto coverage_change = change(QStringLiteral("/observed/latest"));
    coverage_change.coverage_revision = 7;
    coverage_change.rescan_required = true;
    service.ingest_for_tests(subscription, coverage_change);
    QVERIFY(!subscription.acknowledge(captured));
    promoted.reset();
    service.advance_clock_for_tests(4s);
    auto latest = channel->wait(3s);
    QVERIFY(latest && latest->batch.rescan_required);
    if (latest->batch.capture.event_sequence < latest->batch.capture.coverage_sequence) {
        const auto observed_coverage = latest->batch.capture.coverage_sequence;
        QVERIFY(!subscription.acknowledge(latest->batch.capture));
        latest.reset();
        service.advance_clock_for_tests(4s);
        latest = channel->wait(3s);
        QVERIFY(latest && latest->batch.rescan_required);
        QVERIFY(latest->batch.capture.event_sequence >= observed_coverage);
    }
    QVERIFY(subscription.acknowledge(latest->batch.capture));
    QVERIFY(!subscription.rescan_required());
}

void Filesystem_observation_scheduler_tests::rename_endpoints_and_incomplete_detail()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    auto renamed = change(QStringLiteral("/observed/new"));
    renamed.events.front().kind = observation::Event_kind::RENAMED;
    renamed.events.front().old_path = QStringLiteral("/observed/old");
    service.ingest_for_tests(subscription, renamed);
    auto first = channel->wait(3s);
    QVERIFY(first);
    QCOMPARE(first->batch.events.front().old_path, QStringLiteral("/observed/old"));
    QCOMPARE(first->batch.events.front().path, QStringLiteral("/observed/new"));
    first.reset();

    renamed.events.front().old_path.clear();
    renamed.rescan_required = true;
    renamed.diagnostic = QStringLiteral("Rename endpoint unavailable");
    service.ingest_for_tests(subscription, renamed);
    service.advance_clock_for_tests(4s);
    auto partial = channel->wait(3s);
    QVERIFY(partial && partial->batch.rescan_required);
    QVERIFY(!partial->batch.scopes.isEmpty() || partial->batch.all_interests);
    partial.reset();

    observation::Native_batch empty;
    empty.root = QStringLiteral("/observed");
    service.ingest_for_tests(subscription, empty);
    service.advance_clock_for_tests(4s);
    auto missing = channel->wait(3s);
    QVERIFY(missing && missing->batch.rescan_required);
}

void Filesystem_observation_scheduler_tests::partial_rename_reconciles_only_matching_interests()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    observation::Subscription_options options;
    options.classifier = [](const observation::Event& event) {
        return event.path == QStringLiteral("/observed/selected") ||
            event.old_path == QStringLiteral("/observed/selected");
    };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    auto partial = change(QStringLiteral("/observed/unrelated"));
    partial.events.front().kind = observation::Event_kind::RENAMED;
    partial.rescan_required = true;
    partial.rescan_event_paths_complete = true;
    service.ingest_for_tests(subscription, partial);
    QVERIFY(!channel->wait(100ms));
    QVERIFY(!subscription.rescan_required());

    partial.events.front().old_path = QStringLiteral("/observed/selected");
    partial.events.front().path.clear();
    service.ingest_for_tests(subscription, partial);
    auto relevant = channel->wait(3s);
    QVERIFY(relevant && relevant->batch.rescan_required);
    QVERIFY(subscription.acknowledge(relevant->batch.capture));
    relevant.reset();

    partial.events.front().old_path = QStringLiteral("/observed/unrelated");
    partial.rescan_event_paths_complete = false;
    partial.reason = observation::Native_reason::QUEUE_OVERFLOW;
    service.ingest_for_tests(subscription, partial);
    service.advance_clock_for_tests(4s);
    auto lost = channel->wait(3s);
    QVERIFY(lost && lost->batch.rescan_required);
}

void Filesystem_observation_scheduler_tests::obligation_reason_survives_normal_work()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    auto lost = change(QStringLiteral("/observed/a"));
    lost.rescan_required = true;
    lost.diagnostic = QStringLiteral("Native queue overflow");
    service.ingest_for_tests(subscription, lost);
    auto first = channel->wait(3s);
    QVERIFY(first);
    first.reset();
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/b")));
    service.advance_clock_for_tests(4s);
    auto later = channel->wait(3s);
    QVERIFY(later);
    QVERIFY(later->batch.rescan_required);
    QVERIFY(later->batch.diagnostic.contains(QStringLiteral("Native queue overflow")));
    QVERIFY(later->batch.scopes.contains(QStringLiteral("/observed")));
    QVERIFY(subscription.acknowledge(later->batch.capture));
}

void Filesystem_observation_scheduler_tests::consumer_reconciliation_preserves_real_work_data()
{
    QTest::addColumn<int>("reason");
    QTest::newRow("content") << int(observation::Native_reason::CONTENTS_CHANGED);
    QTest::newRow("detail-loss") << int(observation::Native_reason::DETAIL_UNAVAILABLE);
    QTest::newRow("overflow") << int(observation::Native_reason::QUEUE_OVERFLOW);
    QTest::newRow("identity-loss") << int(observation::Native_reason::COVERAGE_CHANGED);
    QTest::newRow("registration-failure") << int(observation::Native_reason::REGISTRATION_FAILED);
}

void Filesystem_observation_scheduler_tests::consumer_reconciliation_preserves_real_work()
{
    QFETCH(int, reason);
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    observation::Native_batch synthetic;
    synthetic.root = synthetic.scope = QStringLiteral("/observed");
    synthetic.rescan_required = true;
    synthetic.consumer_reconciliation_only = true;
    synthetic.diagnostic = QStringLiteral("Owner filter changed");
    service.ingest_for_tests(subscription, synthetic);
    auto first = channel->wait(3s);
    QVERIFY(first && first->batch.consumer_reconciliation_only);
    observation::Native_batch actual;
    actual.root = actual.scope = synthetic.root;
    actual.reason = observation::Native_reason(reason);
    actual.rescan_required = true;
    actual.diagnostic = QStringLiteral("Actual source readback required");
    service.ingest_for_tests(subscription, actual);
    service.ingest_for_tests(subscription, synthetic);
    first.reset();
    service.advance_clock_for_tests(4s);
    auto merged = channel->wait(3s);
    QVERIFY(merged && merged->batch.rescan_required);
    QVERIFY(!merged->batch.consumer_reconciliation_only);
    QCOMPARE(merged->batch.diagnostic, actual.diagnostic);
    QVERIFY(subscription.acknowledge(merged->batch.capture));
    merged.reset();
    service.ingest_for_tests(subscription, synthetic);
    service.advance_clock_for_tests(4s);
    auto fresh = channel->wait(3s);
    QVERIFY(fresh && fresh->batch.consumer_reconciliation_only);
    QCOMPARE(fresh->batch.diagnostic, synthetic.diagnostic);
}

void Filesystem_observation_scheduler_tests::admission_provenance_retains_source_causes_data()
{
    QTest::addColumn<QString>("cause");
    QTest::addColumn<bool>("source_first");
    for (const auto& cause : {"detail", "loss", "promotion"}) {
        QTest::newRow(qPrintable(QStringLiteral("%1-before-admission").arg(cause))) << QString(cause) << true;
        QTest::newRow(qPrintable(QStringLiteral("%1-after-admission").arg(cause))) << QString(cause) << false;
    }
    QTest::newRow("classification-before-admission") << QStringLiteral("classification") << true;
}

void Filesystem_observation_scheduler_tests::admission_provenance_retains_source_causes()
{
    QFETCH(QString, cause);
    QFETCH(bool, source_first);
    observation::limits_t limits;
    limits.retained_events = 2;
    observation::Service service(limits);
    service.use_manual_clock_for_tests();
    observation::Subscription_options options;
    std::atomic_bool classification_failed = false;
    options.classifier = [&cause, &classification_failed](const observation::Event&) {
        if (cause == QStringLiteral("classification")) {
            classification_failed.store(true);
            throw std::runtime_error("Admission detail classification failed");
        }
        return true;
    };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    observation::Native_batch admission;
    admission.root = admission.scope = QStringLiteral("/observed");
    admission.rescan_required = true;
    admission.initial_admission_only = true;
    service.ingest_for_tests(subscription, admission);
    auto first = channel->wait(3s);
    QVERIFY(first && first->batch.rescan_required && first->batch.initial_admission_only);

    observation::Native_batch replan;
    replan.rescan_required = true;
    replan.consumer_reconciliation_only = true;
    service.ingest_for_tests(subscription, replan);
    first.reset();
    service.advance_clock_for_tests(4s);
    auto local = channel->wait(3s);
    QVERIFY(local && local->batch.rescan_required && local->batch.initial_admission_only);

    auto actual = change(QStringLiteral("/observed/changed"));
    if (cause == QStringLiteral("loss")) {
        actual.events.clear();
        actual.rescan_required = true;
        actual.reason = observation::Native_reason::QUEUE_OVERFLOW;
    }
    if (cause == QStringLiteral("promotion")) {
        actual.events.append({QStringLiteral("/observed/second"), {}, observation::Event_kind::MODIFIED});
        actual.events.append({QStringLiteral("/observed/third"), {}, observation::Event_kind::MODIFIED});
    }
    if (!source_first) {
        service.ingest_for_tests(subscription, admission);
    }
    service.ingest_for_tests(subscription, actual);
    if (cause == QStringLiteral("classification")) {
        QVERIFY(wait_until([&] { return classification_failed.load(); }));
    }
    if (source_first) {
        service.ingest_for_tests(subscription, admission);
    }
    local.reset();
    service.advance_clock_for_tests(4s);
    auto merged = channel->wait(3s);
    QVERIFY(merged && merged->batch.rescan_required);
    QVERIFY(!merged->batch.initial_admission_only);
    QVERIFY(!merged->batch.consumer_reconciliation_only);
    if (cause == QStringLiteral("promotion")) {
        QVERIFY(service.statistics().promotions > 0);
    }

    // Dropping a delivery does not discharge its readback. A later local cause
    // cannot erase source work after the event detail has left the pending batch.
    merged.reset();
    service.ingest_for_tests(subscription, replan);
    service.advance_clock_for_tests(4s);
    auto retained = channel->wait(3s);
    QVERIFY(retained && retained->batch.rescan_required);
    QVERIFY(!retained->batch.initial_admission_only);
    QVERIFY(subscription.acknowledge(retained->batch.capture));
    retained.reset();
    service.ingest_for_tests(subscription, admission);
    service.advance_clock_for_tests(4s);
    auto fresh = channel->wait(3s);
    QVERIFY(fresh && fresh->batch.initial_admission_only);
    QVERIFY(subscription.acknowledge(fresh->batch.capture));
}

void Filesystem_observation_scheduler_tests::admission_after_replan_preserves_unacknowledged_source_detail()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    observation::Native_batch replan;
    replan.root = replan.scope = QStringLiteral("/observed");
    replan.rescan_required = true;
    replan.consumer_reconciliation_only = true;
    service.ingest_for_tests(subscription, replan);
    auto local = channel->wait(3s);
    QVERIFY(local && local->batch.consumer_reconciliation_only);

    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/changed")));
    local.reset();
    service.advance_clock_for_tests(4s);
    auto changed = channel->wait(3s);
    QVERIFY(changed && changed->batch.rescan_required);
    QVERIFY(!changed->batch.consumer_reconciliation_only);
    QVERIFY(!changed->batch.initial_admission_only);
    QCOMPARE(changed->batch.events.size(), 1);
    changed.reset();

    // The new root's admission cannot turn the existing unacknowledged source
    // obligation back into local-only work after its detail was delivered.
    observation::Native_batch admission;
    admission.root = admission.scope = QStringLiteral("/observed/new-root");
    admission.rescan_required = true;
    admission.initial_admission_only = true;
    service.ingest_for_tests(subscription, admission);
    service.advance_clock_for_tests(4s);
    auto retained = channel->wait(3s);
    QVERIFY(retained && retained->batch.rescan_required);
    QVERIFY(!retained->batch.consumer_reconciliation_only);
    QVERIFY(!retained->batch.initial_admission_only);
    QVERIFY(subscription.acknowledge(retained->batch.capture));
    retained.reset();

    service.ingest_for_tests(subscription, admission);
    service.advance_clock_for_tests(4s);
    auto fresh = channel->wait(3s);
    QVERIFY(fresh && fresh->batch.initial_admission_only);
    QVERIFY(subscription.acknowledge(fresh->batch.capture));
}

void Filesystem_observation_scheduler_tests::native_admission_is_local_to_new_subscriber()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
#ifdef Q_OS_MACOS
    QVERIFY(complete_native_fixture_setup(directory.path()));
#endif
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{directory.path(), 0}};
    options.mode = observation::Watch_mode::DIRECT;
    options.interval = 20ms;
    auto first_channel = std::make_shared<observation::Wait_channel>();
    auto first = service.subscribe(options, first_channel);
    auto armed = first_channel->wait(3s);
    QVERIFY(armed && armed->batch.rescan_required && armed->batch.initial_admission_only);
    QVERIFY(first.acknowledge(armed->batch.capture));
    armed.reset();

    auto second_channel = std::make_shared<observation::Wait_channel>();
    auto second = service.subscribe(options, second_channel);
    auto admitted = second_channel->wait(3s);
    QVERIFY(admitted && admitted->batch.rescan_required && admitted->batch.initial_admission_only);
    QVERIFY(second.acknowledge(admitted->batch.capture));
    admitted.reset();
    QVERIFY(!first_channel->wait(50ms));

    QFile file(directory.filePath(QStringLiteral("tracked.txt")));
    QVERIFY(file.open(QIODevice::WriteOnly));
    QCOMPARE(file.write("changed"), qint64(7));
    file.close();
    auto first_change = first_channel->wait(3s);
    auto second_change = second_channel->wait(3s);
    QVERIFY(first_change && !first_change->batch.initial_admission_only);
    QVERIFY(second_change && !second_change->batch.initial_admission_only);
}

void Filesystem_observation_scheduler_tests::filter_replan_requires_continuous_coverage_data()
{
    QTest::addColumn<bool>("lose_coverage");
    QTest::newRow("continuous") << false;
    QTest::newRow("native-gap") << true;
}

void Filesystem_observation_scheduler_tests::filter_replan_requires_continuous_coverage()
{
    QFETCH(bool, lose_coverage);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("root"));
    QVERIFY(QDir().mkpath(root + QStringLiteral("/child")));
#ifdef Q_OS_MACOS
    QVERIFY(complete_native_fixture_setup(workspace.path()));
#endif
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{root, 0}};
    options.mode = observation::Watch_mode::RECURSIVE;
    options.interval = 50ms;
    options.directory_filter = [](const QString&, const QString&) { return true; };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
    auto initial = channel->wait(3s);
    QVERIFY(initial && !initial->batch.consumer_reconciliation_only);
    const auto initial_batch = initial->batch;
    const bool initial_acknowledged = subscription.acknowledge(initial_batch.capture);
    auto last_setup_batch = initial_batch;
    bool last_acknowledged = initial_acknowledged;
    initial.reset();
    while (auto delivery = channel->wait(100ms)) {
        last_setup_batch = delivery->batch;
        last_acknowledged = subscription.acknowledge(last_setup_batch.capture);
    }
    if (subscription.rescan_required()) {
        report_observation_batch(QStringLiteral("filter-replan-initial"), &initial_batch);
        report_observation_batch(QStringLiteral("filter-replan-last-setup"), &last_setup_batch);
        report_observation_state(QStringLiteral("filter-replan-setup"), service, subscription, root);
        qInfo() << "Filter-replan setup acknowledgement: initial" << initial_acknowledged
                << "last" << last_acknowledged;
    }
    QVERIFY(!subscription.rescan_required());
    QSemaphore entered;
    QSemaphore resume;
    std::atomic_bool pause = true;
    std::atomic_bool hook_timed_out = false;
    const auto release = qScopeGuard([&] { resume.release(); subscription.reset(); });
    QVERIFY(subscription.replace_directory_filter([&](const QString&, const QString&) {
        if (pause.exchange(false)) {
            entered.release();
            if (!resume.tryAcquire(1, 10000)) {
                hook_timed_out.store(true);
            }
        }
        return true;
    }));
    QVERIFY(entered.tryAcquire(1, 5000));
    auto local = channel->wait(3s);
    QVERIFY(local && local->batch.consumer_reconciliation_only);
    QVERIFY(subscription.acknowledge(local->batch.capture));
    local.reset();
    if (lose_coverage) {
        QVERIFY(service.set_directory_available_for_tests(root, false));
        QTRY_VERIFY_WITH_TIMEOUT(!service.covered_logical_directories_for_tests().contains(root), 5000);
        QVERIFY(service.set_directory_available_for_tests(root, true));
    }
    resume.release();
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
    bool saw_completed_replan = false;
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            saw_completed_replan |= delivery->batch.consumer_reconciliation_only == !lose_coverage;
            subscription.acknowledge(delivery->batch.capture);
        }
        return saw_completed_replan && !subscription.rescan_required();
    }));
    QVERIFY(!hook_timed_out.load());
}

void Filesystem_observation_scheduler_tests::pending_filter_preserves_reconciliation_cause_data()
{
    QTest::addColumn<bool>("previously_covered");
    QTest::addColumn<QString>("source");
    for (const bool covered : {false, true}) {
        for (const auto* source : {"none", "detail", "native-loss"}) {
            const auto name = QStringLiteral("%1-%2")
                .arg(covered ? QStringLiteral("consumer") : QStringLiteral("initial"), QString::fromLatin1(source));
            QTest::newRow(qPrintable(name)) << covered << QString::fromLatin1(source);
        }
    }
}

void Filesystem_observation_scheduler_tests::pending_filter_preserves_reconciliation_cause()
{
    QFETCH(bool, previously_covered);
    QFETCH(QString, source);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root    = workspace.filePath(QStringLiteral("root"));
    const auto payload = root + QStringLiteral("/payload.txt");
    QVERIFY(QDir().mkpath(root + QStringLiteral("/child")));
    QFile file(payload);
    QVERIFY(file.open(QIODevice::WriteOnly));
    QCOMPARE(file.write("before"), qint64(6));
    file.close();
#ifdef Q_OS_MACOS
    QVERIFY(complete_native_fixture_setup(root));
#endif
    const auto pending_filter = [](const QString&, const QString&) -> bool {
        throw observation::Directory_filter_pending();
    };
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{root, 0}};
    options.mode = observation::Watch_mode::RECURSIVE;
    options.interval = 10ms;
    options.directory_filter = previously_covered
        ? observation::Native_watcher::Directory_filter([](const QString&, const QString&) { return true; })
        : observation::Native_watcher::Directory_filter(pending_filter);
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    uint64_t previous_revision = 0;
    uint64_t previous_coverage = 0;
    if (previously_covered) {
        QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
        QVERIFY(wait_until([&] {
            if (auto delivery = channel->wait(20ms)) {
                previous_coverage = delivery->batch.capture.coverage_sequence;
                return subscription.acknowledge(delivery->batch.capture);
            }
            return false;
        }));
        previous_revision = subscription.coverage_revision(root);
        QVERIFY(subscription.replace_directory_filter(pending_filter));
    }
    for (int generation = 0; generation != 2; ++generation) {
        std::optional<observation::Delivery> pending;
        QVERIFY(wait_until([&] {
            pending.reset();
            pending = channel->wait(20ms);
            return pending && pending->batch.capture.coverage_sequence > previous_coverage &&
                subscription.coverage_revision(root) > previous_revision &&
                subscription.coverage_status(root).state == observation::Coverage_state::PENDING;
        }));
        // Eligibility delays subscriber readback without asserting a source
        // change or certifying coverage. Replacing that unfinished plan retains it.
        QVERIFY(pending->batch.rescan_required);
        QVERIFY(pending->batch.events.isEmpty());
        QCOMPARE(pending->batch.initial_admission_only, !previously_covered);
        QCOMPARE(pending->batch.consumer_reconciliation_only, previously_covered);
        QVERIFY(!subscription.covers_directory(root));
        QVERIFY(subscription.coverage_status(root).diagnostic.isEmpty());
        QCOMPARE(service.resource_counts().scan_failed, 0);
        QVERIFY(subscription.acknowledge(pending->batch.capture));
        previous_coverage = pending->batch.capture.coverage_sequence;
        previous_revision = subscription.coverage_revision(root);
        pending.reset();
        if (generation == 0) {
            QVERIFY(subscription.replace_directory_filter(pending_filter));
        }
    }
    if (source == QStringLiteral("detail")) {
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(file.write("changed"), qint64(7));
        file.close();
        std::optional<observation::Delivery> detail;
        QVERIFY(wait_until([&] {
            detail.reset();
            detail = channel->wait(20ms);
            return detail && std::any_of(detail->batch.events.cbegin(), detail->batch.events.cend(),
                [&](const auto& event) { return event.path == payload; });
        }));
        QVERIFY(!detail->batch.initial_admission_only);
        QVERIFY(!detail->batch.consumer_reconciliation_only);
        QVERIFY(subscription.acknowledge(detail->batch.capture));
    }
    else
    if (source == QStringLiteral("native-loss")) {
        QVERIFY(service.set_directory_available_for_tests(root, false));
        QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).state,
            observation::Coverage_state::FAILED, 5000);
        QVERIFY(service.set_directory_available_for_tests(root, true));
        QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).state,
            observation::Coverage_state::PENDING, 5000);
    }
    QVERIFY(subscription.replace_directory_filter([](const QString&, const QString&) { return true; }));
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
    std::optional<observation::Delivery> armed;
    QVERIFY(wait_until([&] {
        armed.reset();
        armed = channel->wait(20ms);
        return armed && armed->batch.capture.coverage_sequence > previous_coverage &&
            subscription.acknowledge(armed->batch.capture);
    }));
    const bool local = source == QStringLiteral("none");
    QVERIFY(armed->batch.rescan_required);
    QCOMPARE(armed->batch.initial_admission_only, local && !previously_covered);
    QCOMPARE(armed->batch.consumer_reconciliation_only, local && previously_covered);
    QVERIFY(!subscription.rescan_required());
    previous_coverage = armed->batch.capture.coverage_sequence;
    previous_revision = subscription.coverage_revision(root);
    armed.reset();
    // Accepted source readback and restored coverage allow the next owner
    // replan to begin a fresh consumer obligation.
    QVERIFY(subscription.replace_directory_filter([](const QString&, const QString&) { return true; }));
    QTRY_VERIFY_WITH_TIMEOUT(subscription.coverage_revision(root) > previous_revision &&
        subscription.covers_directory(root), 5000);
    std::optional<observation::Delivery> fresh;
    QVERIFY(wait_until([&] {
        fresh.reset();
        fresh = channel->wait(20ms);
        return fresh && fresh->batch.capture.coverage_sequence > previous_coverage &&
            subscription.acknowledge(fresh->batch.capture);
    }));
    QVERIFY(fresh->batch.rescan_required);
    QVERIFY(fresh->batch.consumer_reconciliation_only);
    QVERIFY(!fresh->batch.initial_admission_only);
    QVERIFY(!subscription.rescan_required());
}

void Filesystem_observation_scheduler_tests::injected_unavailability_survives_directory_restoration()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root  = workspace.filePath(QStringLiteral("root"));
    const auto saved = workspace.filePath(QStringLiteral("saved"));
    QVERIFY(QDir().mkpath(root));
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{root, 0}};
    options.interval = 50ms;
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);

    QVERIFY(QDir().rename(root, saved));
    QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).state, observation::Coverage_state::FAILED, 5000);
    const auto injected = QStringLiteral("Injected native directory unavailability");
    QVERIFY(service.set_directory_available_for_tests(root, false));
    QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).diagnostic, injected, 5000);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::FAILED);

    // Releasing the injection must expose the real missing directory, not claim coverage.
    QVERIFY(service.set_directory_available_for_tests(root, true));
    QTRY_VERIFY_WITH_TIMEOUT(subscription.coverage_status(root).diagnostic != injected &&
        !subscription.coverage_status(root).diagnostic.isEmpty(), 5000);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::FAILED);
    QVERIFY(!subscription.covers_directory(root));

    QVERIFY(service.set_directory_available_for_tests(root, false));
    QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).diagnostic, injected, 5000);
#ifdef Q_OS_WIN
    const auto missing_revision = subscription.coverage_revision(root);
#endif
    QVERIFY(QDir().rename(saved, root));
#ifdef Q_OS_WIN
    // Injection must not suspend Windows' independent physical-identity validation.
    QTRY_VERIFY_WITH_TIMEOUT(subscription.coverage_revision(root) > missing_revision, 5000);
#endif
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::FAILED);
    QCOMPARE(subscription.coverage_status(root).diagnostic, injected);
    QVERIFY(!subscription.covers_directory(root));

    QVERIFY(service.set_directory_available_for_tests(root, true));
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
    QVERIFY(subscription.coverage_status(root).diagnostic.isEmpty());
}

void Filesystem_observation_scheduler_tests::pending_filter_delivers_once_and_recovers()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("root"));
    QVERIFY(QDir().mkpath(root + QStringLiteral("/child")));
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{root, 0}};
    options.mode = observation::Watch_mode::RECURSIVE;
    options.interval = 50ms;
    options.directory_filter = [](const QString&, const QString&) -> bool {
        throw observation::Directory_filter_pending();
    };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::PENDING);
    const auto initial_deadline = std::chrono::steady_clock::now() + 5s;
    auto pending = channel->wait(5s);
    // Native detail can precede the asynchronous eligibility attempt. Freeze the
    // synthetic events' revision only after its completed pending epoch arrives.
    while (pending && pending->batch.capture.coverage_sequence == 0) {
        pending.reset();
        const auto remaining = initial_deadline - std::chrono::steady_clock::now();
        QVERIFY(remaining > 0s);
        pending = channel->wait(std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
    }
    QVERIFY(pending);
    QVERIFY(pending->batch.capture.coverage_sequence != 0);
    QVERIFY(!pending->batch.consumer_reconciliation_only);
    QVERIFY(!subscription.covers_directory(root));
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::PENDING);
    QVERIFY(subscription.coverage_status(root).diagnostic.isEmpty());
    QCOMPARE(service.resource_counts().scan_failed, 0);
    const auto capture = pending->batch.capture;
    observation::Native_batch ordinary;
    ordinary.root = ordinary.scope = root;
    ordinary.coverage_revision = subscription.coverage_revision(root);
    QVERIFY(ordinary.coverage_revision != 0);
    ordinary.events.append({root + QStringLiteral("/observed.txt"), {}, observation::Event_kind::MODIFIED});
    service.ingest_for_tests(subscription, ordinary);
    pending.reset();
    auto merged = channel->wait(3s);
    QVERIFY(merged && merged->batch.rescan_required);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::PENDING);
    QVERIFY(subscription.coverage_status(root).diagnostic.isEmpty());
    QVERIFY(subscription.acknowledge(merged->batch.capture));
    merged.reset();
    service.ingest_for_tests(subscription, ordinary);
    auto after_ack = channel->wait(3s);
    QVERIFY(after_ack && !after_ack->batch.rescan_required);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::PENDING);
    QVERIFY(subscription.acknowledge(after_ack->batch.capture));
    after_ack.reset();
    // The existing one-second retry may remain pending without a new capture.
    QVERIFY(!channel->wait(1200ms));
    observation::Native_batch loss;
    loss.root = loss.scope = root;
    loss.rescan_required = true;
    loss.reason = observation::Native_reason::QUEUE_OVERFLOW;
    service.ingest_for_tests(subscription, loss);
    auto lost = channel->wait(3s);
    QVERIFY(lost && !lost->batch.consumer_reconciliation_only);
    QVERIFY(service.set_directory_available_for_tests(root, false));
    QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).state, observation::Coverage_state::FAILED, 5000);
    QCOMPARE(subscription.coverage_status(root).diagnostic, QStringLiteral("Injected native directory unavailability"));
    QVERIFY(service.set_directory_available_for_tests(root, true));
    QTRY_COMPARE_WITH_TIMEOUT(subscription.coverage_status(root).state, observation::Coverage_state::PENDING, 5000);
    QVERIFY(subscription.replace_directory_filter([](const QString&, const QString&) { return true; }));
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(root), 5000);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::COVERED);
    QVERIFY(subscription.coverage_status(root).diagnostic.isEmpty());
    QVERIFY(subscription.rescan_required());
    lost.reset();
    bool recovered = false;
    bool real_loss_preserved = true;
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            recovered |= delivery->batch.capture.event_sequence > capture.event_sequence;
            real_loss_preserved &= !delivery->batch.consumer_reconciliation_only;
            subscription.acknowledge(delivery->batch.capture);
        }
        return recovered && !subscription.rescan_required();
    }));
    QVERIFY(real_loss_preserved);
    QCOMPARE(service.resource_counts().scan_failed, 0);
}

void Filesystem_observation_scheduler_tests::retained_descendant_loss_reconciles_pending_filter()
{
    // A retained descendant still protects a pending replacement plan. Its loss
    // must invalidate old captures and publish a new reconcilable coverage epoch.
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("root"));
    const auto child = root + QStringLiteral("/child");
    QVERIFY(QDir().mkpath(child));
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{root, 0}};
    options.mode = observation::Watch_mode::RECURSIVE;
    options.interval = 50ms;
    options.directory_filter = [](const QString&, const QString&) { return true; };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    observation::capture_t initial_capture;
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            initial_capture = delivery->batch.capture;
            return subscription.covers_directory(root) && subscription.acknowledge(initial_capture);
        }
        return false;
    }));
    const auto initial_revision = subscription.coverage_revision(root);
    QVERIFY(subscription.replace_directory_filter([](const QString&, const QString&) -> bool {
        throw observation::Directory_filter_pending();
    }));
    std::optional<observation::Delivery> pending;
    QVERIFY(wait_until([&] {
        pending.reset();
        pending = channel->wait(20ms);
        return pending && pending->batch.capture.coverage_sequence > initial_capture.coverage_sequence &&
            subscription.coverage_revision(root) > initial_revision;
    }));
    QVERIFY(pending->batch.rescan_required);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::PENDING);
    QVERIFY(service.covered_logical_directories_for_tests().contains(child));
    const auto pending_revision = subscription.coverage_revision(root);
    const auto pending_capture = pending->batch.capture;

    QVERIFY(service.set_directory_available_for_tests(child, false));
    QTRY_VERIFY_WITH_TIMEOUT(!service.covered_logical_directories_for_tests().contains(child), 5000);
    QVERIFY(subscription.coverage_revision(root) > pending_revision);
    QVERIFY(!subscription.acknowledge(pending_capture));
    pending.reset();
    auto reconciled = channel->wait(3s);
    QVERIFY2(reconciled, "Known retained-descendant loss published no replacement capture");
    QVERIFY(reconciled->batch.rescan_required);
    QVERIFY(!reconciled->batch.consumer_reconciliation_only);
    QVERIFY(reconciled->batch.capture.coverage_sequence > pending_capture.coverage_sequence);
    QCOMPARE(subscription.coverage_status(root).state, observation::Coverage_state::PENDING);
    QVERIFY(subscription.acknowledge(reconciled->batch.capture));
    QVERIFY(!subscription.rescan_required());
    reconciled.reset();
    // The same unresolved eligibility result does not create another obligation.
    QVERIFY(!channel->wait(1200ms));
}

void Filesystem_observation_scheduler_tests::detail_during_reconciliation_does_not_extend_obligation()
{
    // A rescan obligation covers the state captured with it. Detail observed while the
    // receiver reconciles stays detail; it must not keep the obligation open.
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    auto lost = change(QStringLiteral("/observed/a"));
    lost.rescan_required = true;
    lost.diagnostic = QStringLiteral("Native queue overflow");
    service.ingest_for_tests(subscription, lost);
    for (int round = 0; round < 3; ++round) {
        auto delivery = channel->wait(3s);
        QVERIFY(delivery);
        QCOMPARE(delivery->batch.rescan_required, round == 0);
        if (round > 0) {
            QCOMPARE(delivery->batch.events.size(), 1);
            QCOMPARE(delivery->batch.events.front().path,
                QStringLiteral("/observed/during-%1").arg(round - 1));
        }
        const auto capture = delivery->batch.capture;
        delivery->completion.complete();
        service.ingest_for_tests(subscription, change(QStringLiteral("/observed/during-%1").arg(round)));
        QVERIFY(subscription.acknowledge(capture));
        QVERIFY(!subscription.rescan_required());
        service.advance_clock_for_tests(4s);
    }
}

void Filesystem_observation_scheduler_tests::one_shot_acknowledgement_during_classification_data()
{
    QTest::addColumn<bool>("relevant");
    QTest::addColumn<bool>("classification_fails");
    QTest::newRow("irrelevant-detail")      << false << false;
    QTest::newRow("relevant-detail")        << true  << false;
    QTest::newRow("classification-failure") << false << true;
}

void Filesystem_observation_scheduler_tests::one_shot_acknowledgement_during_classification()
{
    QFETCH(bool, relevant);
    QFETCH(bool, classification_fails);
    observation::Service service;
    service.use_manual_clock_for_tests();
    std::atomic_bool entered{false};
    std::atomic_bool release{false};
    observation::Subscription_options options;
    options.classifier = [&](const observation::Event&) {
        entered.store(true);
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
        if (classification_fails) {
            throw std::runtime_error("Classifier failed after reconciliation");
        }
        return relevant;
    };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    const auto finish = qScopeGuard([&] { release.store(true); });
    auto lost = change(QStringLiteral("/observed/tracked.txt"));
    lost.rescan_required = true;
    service.ingest_for_tests(subscription, lost);
    auto delivery = channel->wait(3s);
    QVERIFY(delivery);
    const auto capture = delivery->batch.capture;
    delivery->completion.complete();
    service.ingest_for_tests(subscription, change(QStringLiteral("/observed/detail.txt")));
    QVERIFY(wait_until([&] { return entered.load(); }));
    const bool accepted = subscription.acknowledge(capture);
    release.store(true);
    service.advance_clock_for_tests(4s);
    QVERIFY(accepted);
    if (relevant || classification_fails) {
        auto newer = channel->wait(3s);
        QVERIFY(newer);
        QCOMPARE(newer->batch.rescan_required, classification_fails);
        if (classification_fails) {
            QVERIFY(subscription.rescan_required());
            QVERIFY(!subscription.acknowledge(capture));
            QVERIFY(subscription.acknowledge(newer->batch.capture));
        }
        else {
            QCOMPARE(newer->batch.events.size(), 1);
            QCOMPARE(newer->batch.events.front().path, QStringLiteral("/observed/detail.txt"));
        }
    }
    else {
        QVERIFY(!channel->wait(100ms));
    }
    QVERIFY(!subscription.rescan_required());
}

void Filesystem_observation_scheduler_tests::coverage_transition_bypasses_content_classifier()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    auto channel = std::make_shared<observation::Wait_channel>();
    observation::Subscription_options options;
    options.classifier = [](const observation::Event&) { return false; };
    auto subscription = service.subscribe(options, channel);
    auto unrelated = change(QStringLiteral("/observed/irrelevant"));
    service.ingest_for_tests(subscription, unrelated);
    QVERIFY(!channel->wait(20ms));
    unrelated.coverage_revision = 1;
    service.ingest_for_tests(subscription, unrelated);
    auto coverage = channel->wait(1s);
    QVERIFY(coverage);
    QVERIFY(coverage->batch.rescan_required);
    QVERIFY(subscription.acknowledge(coverage->batch.capture));
}

void Filesystem_observation_scheduler_tests::unsubscribe_replacement_and_shutdown()
{
    observation::Service service;
    QCOMPARE(service.statistics().control_threads, size_t(2));
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe({}, channel);
    subscription.request_rescan(QStringLiteral("Reconcile"));
    auto held = channel->wait(3s);
    QVERIFY(held);
    const auto capture = held->batch.capture;
    subscription.reset();
    QVERIFY(!held->valid());
    QVERIFY(!channel->wait(1s));

    auto replacement_channel = std::make_shared<observation::Wait_channel>();
    auto replacement = service.subscribe({}, replacement_channel);
    QVERIFY(!replacement.acknowledge(capture));
    auto waiter = std::async(std::launch::async, [&] { return replacement_channel->wait(1h); });
    service.shutdown();
    QCOMPARE(service.statistics().control_threads, size_t(0));
    QCOMPARE(waiter.wait_for(3s), std::future_status::ready);
    QVERIFY(!waiter.get());
    held.reset();
}

void Filesystem_observation_scheduler_tests::reset_waits_for_running_classifier()
{
    // A receiver may destroy what its classifier uses as soon as reset() returns.
    observation::Service service;
    auto channel = std::make_shared<observation::Wait_channel>();
    std::atomic_bool entered{false};
    std::atomic_bool release{false};
    std::atomic_bool reset_returned{false};
    std::atomic_int calls_after_reset{0};
    observation::Subscription_options options;
    options.classifier = [&](const observation::Event&) {
        if (reset_returned.load()) {
            ++calls_after_reset;
        }
        entered.store(true);
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
        return true;
    };
    auto subscription = service.subscribe(options, channel);
    std::thread resetting;
    const auto finish = qScopeGuard([&] {
        release.store(true);
        if (resetting.joinable()) {
            resetting.join();
        }
    });
    auto batch = change(QStringLiteral("/observed/first"));
    batch.events.append({QStringLiteral("/observed/second"), {}, observation::Event_kind::MODIFIED});
    service.ingest_for_tests(subscription, batch);
    QVERIFY(wait_until([&] { return entered.load(); }));
    resetting = std::thread([&] {
        subscription.reset();
        reset_returned.store(true);
    });
    std::this_thread::sleep_for(100ms);
    QVERIFY(!reset_returned.load());
    release.store(true);
    resetting.join();
    // The second event must not reach the classifier of a reset subscription.
    std::this_thread::sleep_for(50ms);
    QCOMPARE(calls_after_reset.load(), 0);
    QVERIFY(!channel->wait(10ms));
}

void Filesystem_observation_scheduler_tests::classifier_may_reset_its_own_subscription()
{
    observation::Service service;
    auto channel = std::make_shared<observation::Wait_channel>();
    observation::Subscription subscription;
    std::atomic_int calls{0};
    std::atomic_bool reset_inside{false};
    observation::Subscription_options options;
    options.classifier = [&](const observation::Event&) {
        ++calls;
        subscription.reset();
        reset_inside.store(true);
        return true;
    };
    subscription = service.subscribe(options, channel);
    auto batch = change(QStringLiteral("/observed/first"));
    batch.events.append({QStringLiteral("/observed/second"), {}, observation::Event_kind::MODIFIED});
    service.ingest_for_tests(subscription, batch);
    QVERIFY(wait_until([&] { return reset_inside.load(); }));

    // The scheduler returned from its own unsubscription and still serves others.
    auto other_channel = std::make_shared<observation::Wait_channel>();
    auto other = service.subscribe({}, other_channel);
    service.ingest_for_tests(other, change(QStringLiteral("/observed/other")));
    QVERIFY(other_channel->wait(3s));
    QCOMPARE(calls.load(), 1);
    QVERIFY(!channel->wait(10ms));
}

#ifdef Q_OS_LINUX
void Filesystem_observation_scheduler_tests::reset_retires_directory_filter()
{
    // A subscriber's directory filter must not run after reset() returns, although
    // its native registration retires asynchronously.
    QTemporaryDir root;
    QVERIFY(root.isValid());
    for (const auto name : {"first", "second", "third"}) {
        QVERIFY(QDir().mkpath(root.filePath(QString::fromLatin1(name))));
    }
    observation::Service service;
    auto channel = std::make_shared<observation::Wait_channel>();
    std::atomic_bool entered{false};
    std::atomic_bool release{false};
    std::atomic_bool reset_returned{false};
    std::atomic_int calls_after_reset{0};
    observation::Subscription_options options;
    options.directories.append({root.path(), 0});
    options.directory_filter = [&](const QString&, const QString&) {
        if (reset_returned.load()) {
            ++calls_after_reset;
        }
        entered.store(true);
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
        return true;
    };
    auto subscription = service.subscribe(options, channel);
    std::thread resetting;
    const auto finish = qScopeGuard([&] {
        release.store(true);
        if (resetting.joinable()) {
            resetting.join();
        }
    });
    QVERIFY(wait_until([&] { return entered.load(); }));
    resetting = std::thread([&] {
        subscription.reset();
        reset_returned.store(true);
    });
    std::this_thread::sleep_for(100ms);
    QVERIFY(!reset_returned.load());
    release.store(true);
    resetting.join();
    QVERIFY(QDir().mkpath(root.filePath(QStringLiteral("created-after-reset"))));
    QVERIFY(wait_until([&] {
        const auto statistics = service.statistics();
        return statistics.retiring_groups == 0 && statistics.pending_registrations == 0;
    }));
    QCOMPARE(calls_after_reset.load(), 0);
}
#endif

void Filesystem_observation_scheduler_tests::qt_dropped_event_releases_delivery()
{
    observation::Service service;
    service.use_manual_clock_for_tests();
    QObject receiver;
    int calls = 0;
    auto channel = std::make_shared<observation::Qt_delivery>(&receiver,
        [&](observation::Delivery) { ++calls; });
    auto subscription = service.subscribe({}, channel);
    subscription.request_rescan(QStringLiteral("Queued reconciliation"));
    QVERIFY(wait_until([&] { return service.statistics().outstanding == 1; }));
    // submit follows slot acquisition; wait until the queued event has been posted.
    // Removal may precede submit, so bounded repetition stops when completion arrives.
    QVERIFY(wait_until([&] {
        QCoreApplication::removePostedEvents(&receiver, QEvent::MetaCall);
        return service.statistics().outstanding == 0;
    }));
    QCOMPARE(calls, 0);
    QVERIFY(subscription.rescan_required());
    subscription.request_rescan(QStringLiteral("Final reconciliation"));
    service.advance_clock_for_tests(4s);
    QVERIFY(wait_until([&] { return service.statistics().outstanding == 1; }));
    channel->cancel();
    QCoreApplication::sendPostedEvents(&receiver, QEvent::MetaCall);
    QCOMPARE(calls, 0);
    subscription.reset();
}

void Filesystem_observation_scheduler_tests::native_delivery_without_calling_event_loop()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    observation::Service service;
    auto channel = std::make_shared<observation::Wait_channel>();
    observation::Subscription_options options;
    options.directories.append({directory.path(), 0});
    options.interval = 20ms;
    auto subscription = service.subscribe(options, channel);
    QVERIFY(wait_until([&] { return subscription.covers_directory(directory.path()); }));
    // Clear the arm/reconciliation notification before the real content mutation.
    while (auto armed = channel->wait(30ms)) {
        subscription.acknowledge(armed->batch.capture);
    }
    const auto path = directory.filePath(QStringLiteral("tracked.txt"));
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly));
    QCOMPARE(file.write("updated"), qint64(7));
    file.close();
    auto delivery = channel->wait(5s);
    QVERIFY(delivery);
    QVERIFY(delivery->batch.rescan_required ||
        std::any_of(delivery->batch.events.begin(), delivery->batch.events.end(), [&](const auto& event) {
            return event.path == path;
        }));
}

void Filesystem_observation_scheduler_tests::qt_cancel_serializes_with_receiver_destruction()
{
    for (int iteration = 0; iteration < 64; ++iteration) {
        auto receiver = std::make_unique<QObject>();
        std::atomic_int releases{0};
        int callbacks = 0;
        auto channel = std::make_shared<observation::Qt_delivery>(receiver.get(),
            [&](observation::Delivery) { ++callbacks; });
        observation::Delivery delivery;
        delivery.active = std::make_shared<std::atomic_bool>(true);
        delivery.completion = observation::Completion([&] { ++releases; });
        std::latch ready(1);
        std::latch start(1);
        std::thread submitter([&, delivery = std::move(delivery)]() mutable {
            ready.count_down();
            start.wait();
            channel->submit(std::move(delivery));
        });
        ready.wait();
        start.count_down();
        channel->cancel();
        receiver.reset();
        submitter.join();
        QCOMPARE(callbacks, 0);
        QCOMPARE(releases.load(), 1);
    }
}

void Filesystem_observation_scheduler_tests::native_shared_subscribers_progress_while_one_is_held()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    observation::Service service;
    observation::Subscription_options options;
    options.directories.append({directory.path(), 0});
    // Exact default intervals belong to the manual-clock scheduling test.
    options.interval = 10ms;
    auto general_channel = std::make_shared<observation::Wait_channel>();
    auto general = service.subscribe(options, general_channel);
    QVERIFY(wait_until([&] { return general.covers_directory(directory.path()); }));
    const auto first_resources = service.resource_counts();
    options.interval = 5ms;
    auto document_channel = std::make_shared<observation::Wait_channel>();
    auto document = service.subscribe(options, document_channel);
    QVERIFY(wait_until([&] { return document.covers_directory(directory.path()); }));
    QCOMPARE(service.resource_counts().desired, first_resources.desired);
    QCOMPARE(service.resource_counts().native_threads, first_resources.native_threads);
    while (auto armed = general_channel->wait(30ms)) {
        general.acknowledge(armed->batch.capture);
    }
    while (auto armed = document_channel->wait(30ms)) {
        document.acknowledge(armed->batch.capture);
    }
    const auto write = [](const QString& path, const QByteArray& contents) {
        QFile file(path);
        return file.open(QIODevice::WriteOnly) && file.write(contents) == contents.size();
    };
    const auto wait_for_path = [](
            observation::Subscription& subscription,
            observation::Wait_channel& channel,
            const QString& path)
        {
            const auto end = std::chrono::steady_clock::now() + 3s;
            while (std::chrono::steady_clock::now() < end) {
                auto delivery = channel.wait(std::chrono::duration_cast<std::chrono::milliseconds>(
                    end - std::chrono::steady_clock::now()));
                if (!delivery) {
                    return delivery;
                }
                subscription.acknowledge(delivery->batch.capture);
                if (std::any_of(delivery->batch.events.begin(), delivery->batch.events.end(),
                    [&](const auto& event) { return event.path == path; }))
                {
                    return delivery;
                }
            }
            return std::optional<observation::Delivery>{};
        };
    const auto tracked = directory.filePath(QStringLiteral("tracked.txt"));
    QVERIFY(write(tracked, "leading"));
    auto held = wait_for_path(general, *general_channel, tracked);
    auto leading_document = wait_for_path(document, *document_channel, tracked);
    QVERIFY(held && leading_document);
    leading_document.reset();

    for (int i = 0; i < 3; ++i) {
        const auto path = directory.filePath(QStringLiteral("change-%1.txt").arg(i));
        QVERIFY(write(path, QByteArray::number(i)));
        QVERIFY(wait_for_path(document, *document_channel, path));
        QVERIFY(!general_channel->wait(0ms));
        QVERIFY(service.statistics().outstanding <= 2);
    }
    const auto nested = directory.filePath(QStringLiteral("nested"));
    QVERIFY(QDir().mkpath(nested));
    // The child is discovered recursively; only the parent is a registered interest.
    QVERIFY(wait_until([&] {
        return service.covered_logical_directories_for_tests().contains(nested) &&
            document.covers_directory(directory.path());
    }));
    const auto final_path = nested + QStringLiteral("/final.txt");
    QVERIFY(write(final_path, "final state"));
    QVERIFY(wait_for_path(document, *document_channel, final_path));
    QVERIFY(!general_channel->wait(0ms));
    held.reset();
    auto final_union = general_channel->wait(3s);
    QVERIFY(final_union);
    QVERIFY(std::any_of(final_union->batch.events.begin(), final_union->batch.events.end(),
        [&](const auto& event) { return event.path == final_path; }));
}

void Filesystem_observation_scheduler_tests::direct_overlapping_interests_share_native_owner()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto shared = workspace.filePath(QStringLiteral("shared"));
    const auto first_only = workspace.filePath(QStringLiteral("first"));
    const auto second_only = workspace.filePath(QStringLiteral("second"));
    for (const auto& path : {shared, first_only, second_only}) {
        QVERIFY(QDir().mkpath(path));
    }
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DIRECT;
    options.directories = {{shared, 0}, {first_only, 0}};
    auto first_channel = std::make_shared<observation::Wait_channel>();
    auto first = service.subscribe(options, first_channel);
    options.directories = {{shared, 0}, {second_only, 0}};
    auto second_channel = std::make_shared<observation::Wait_channel>();
    auto second = service.subscribe(options, second_channel);
    QVERIFY(wait_until([&] {
        return first.covers_directory(shared) && first.covers_directory(first_only) &&
            second.covers_directory(shared) && second.covers_directory(second_only);
    }));
    // Different logical path sets still share a bounded physical dispatch owner.
    QCOMPARE(service.resource_counts().native_threads, 2);
    // Windows owns the shared recursive ancestor; Linux owns each directory.
#ifdef Q_OS_WIN
    QCOMPARE(service.resource_counts().desired, 1);
    QCOMPARE(service.resource_counts().armed, 1);
#else
    QCOMPARE(service.resource_counts().desired, 4);
    QCOMPARE(service.resource_counts().armed, 4);
#endif
    QCOMPARE(service.resource_counts().failed, 0);
}

void Filesystem_observation_scheduler_tests::recursive_and_direct_interests_share_physical_union()
{
    // Oracle: recursive eligibility and explicit fetched-directory membership
    // form one physical union, while captures and receiver lifetimes stay local.
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const QString root = workspace.filePath(QStringLiteral("root"));
    const QString child = root + QStringLiteral("/child");
    const QString grandchild = child + QStringLiteral("/grandchild");
    QVERIFY(QDir().mkpath(grandchild));
    const QString file = child + QStringLiteral("/settings.ini");
    const auto write = [&](const QByteArray& contents) {
        QFile output(file);
        return output.open(QIODevice::WriteOnly) && output.write(contents) == contents.size();
    };
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::RECURSIVE;
    options.interval = 50ms;
    options.directories = {{root, 0}};
    auto recursive_channel = std::make_shared<observation::Wait_channel>();
    auto recursive = service.subscribe(options, recursive_channel);
    options.mode = observation::Watch_mode::DIRECT;
    options.interval = 100ms;
    options.directories = {{child, 0}};
    auto direct_channel = std::make_shared<observation::Wait_channel>();
    auto direct = service.subscribe(options, direct_channel);
    QVERIFY(wait_until([&] {
        return recursive.covers_directory(root) && direct.covers_directory(child);
    }));
    const auto counts = service.resource_counts();
    qInfo() << "Recursive and DIRECT physical union" << "desired" << counts.desired
            << "armed" << counts.armed << "failed" << counts.failed
            << "native_threads" << counts.native_threads;
    QCOMPARE(counts.native_threads, 2);
    // Logical eligibility is shared without opening descendant Windows handles.
#ifdef Q_OS_WIN
    QCOMPARE(counts.desired, 1);
    QCOMPARE(counts.armed, 1);
    QCOMPARE(counts.covered_logical_directories, 4);
#else
    QCOMPARE(counts.desired, 4);
    QCOMPARE(counts.armed, 4);
#endif
    QCOMPARE(counts.failed, 0);

    const auto has_file = [&](const observation::Delivery& delivery) {
        return std::any_of(delivery.batch.events.cbegin(), delivery.batch.events.cend(),
            [&](const auto& event) { return event.path == file; });
    };
    QList<observation::Batch> acknowledged_initial_batches;
    const auto acquire = [&](observation::Subscription& subscription,
        observation::Wait_channel& channel, const QStringList& directories,
        const QByteArray& expected_contents)
    {
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        bool saw_file = expected_contents.isEmpty();
        while (std::chrono::steady_clock::now() < deadline) {
            auto delivery = channel.wait(100ms);
            if (!delivery) {
                continue;
            }
            // Acquire after this capture. If a newer rescan invalidates it,
            // retain the obligation and acquire again under its successor.
            for (const auto& directory : directories) {
                (void)QDir(directory).entryList(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot);
            }
            saw_file |= has_file(*delivery);
            if (!expected_contents.isEmpty()) {
                QFile input(file);
                if (!input.open(QIODevice::ReadOnly) || input.readAll() != expected_contents) {
                    return false;
                }
            }
            if (saw_file && subscription.acknowledge(delivery->batch.capture)) {
                if (expected_contents.isEmpty()) {
                    acknowledged_initial_batches.append(delivery->batch);
                }
                return true;
            }
        }
        return false;
    };
    QVERIFY(acquire(recursive, *recursive_channel, {root, child, grandchild}, {}));
    QVERIFY(acquire(direct, *direct_channel, {child}, {}));
    QVERIFY(write("leading edit"));
    // A directory timestamp change can lead the file notification. Complete
    // that acquisition so the subscription can deliver the file.
    const auto leading_deadline = std::chrono::steady_clock::now() + 3s;
    std::optional<observation::Batch> preceding_batch;
    std::optional<observation::Delivery> held;
    while (std::chrono::steady_clock::now() < leading_deadline) {
        const auto remaining = leading_deadline - std::chrono::steady_clock::now();
        held = recursive_channel->wait(std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
        if (!held || has_file(*held)) {
            break;
        }
        for (const auto& directory : {root, child, grandchild}) {
            (void)QDir(directory).entryList(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot);
        }
        QFile input(file);
        QVERIFY(input.open(QIODevice::ReadOnly));
        QCOMPARE(input.readAll(), QByteArray("leading edit"));
        input.close();
        recursive.acknowledge(held->batch.capture);
        preceding_batch = held->batch;
        held.reset();
    }
    if (!held || !has_file(*held)) {
        for (const auto& batch : acknowledged_initial_batches) {
            report_observation_batch(QStringLiteral("initial-acknowledged"), &batch);
        }
        if (preceding_batch) {
            report_observation_batch(QStringLiteral("preceding-recursive-batch"), &*preceding_batch);
        }
        report_observation_batch(QStringLiteral("recursive-held"), held ? &held->batch : nullptr);
        report_observation_state(QStringLiteral("recursive-held-state"), service, recursive, root);
        report_observation_state(QStringLiteral("direct-held-state"), service, direct, child);
    }
    QVERIFY(held && has_file(*held));
    QVERIFY(!direct.acknowledge(held->batch.capture));
    QVERIFY(acquire(direct, *direct_channel, {child}, "leading edit"));
    QVERIFY(write("final edit while recursive receiver is held"));
    QVERIFY(acquire(direct, *direct_channel, {child},
        "final edit while recursive receiver is held"));
    QVERIFY(!recursive_channel->wait(20ms));

    recursive.reset();
    held.reset();
#ifdef Q_OS_WIN
    constexpr int k_remaining_native = 1;
#else
    constexpr int k_remaining_native = 2;
#endif
    QVERIFY(wait_until([&] {
        return service.statistics().subscriptions == 1 &&
            service.resource_counts().desired == k_remaining_native &&
            service.resource_counts().armed == k_remaining_native;
    }));
    QCOMPARE(service.resource_counts().native_threads, 2);
    QCOMPARE(service.resource_counts().failed, 0);
    QVERIFY(direct.covers_directory(child));
    QVERIFY(write("edit after recursive retirement"));
    QVERIFY(acquire(direct, *direct_channel, {child}, "edit after recursive retirement"));
    direct.reset();
    QVERIFY(wait_until([&] {
        const auto remaining = service.resource_counts();
        return remaining.desired == 0 && remaining.armed == 0 &&
            remaining.failed == 0 && remaining.native_threads == 0;
    }));
}

void Filesystem_observation_scheduler_tests::unchanged_expansion_failure_retains_coverage_obligation_data()
{
    QTest::addColumn<bool>("lose_descendant");
    QTest::newRow("same-failure-retries") << false;
    QTest::newRow("new-descendant-loss") << true;
}

void Filesystem_observation_scheduler_tests::unchanged_expansion_failure_retains_coverage_obligation()
{
    QFETCH(bool, lose_descendant);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("root"));
    const auto healthy = root + QStringLiteral("/healthy");
    const auto pending = root + QStringLiteral("/pending");
    QVERIFY(QDir().mkpath(healthy));
    std::atomic_bool allow = false;
    std::atomic_int attempts = 0;
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::RECURSIVE;
    options.directories = {{root, 0}};
    options.interval = 50ms;
    options.directory_filter = [&](const QString&, const QString& path) {
        if (path == pending && !allow.load()) {
            ++attempts;
            throw std::runtime_error("Eligibility unavailable");
        }
        return true;
    };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    const auto release = qScopeGuard([&] {
        service.set_directory_available_for_tests(healthy, true);
        subscription.reset();
    });
    QVERIFY(wait_until([&] { return subscription.covers_directory(root); }));
    while (auto initial = channel->wait(100ms)) {
        subscription.acknowledge(initial->batch.capture);
    }
    QVERIFY(QDir().mkpath(pending));
    const auto file = pending + QStringLiteral("/final.txt");
    {
        QFile output(file);
        QVERIFY(output.open(QIODevice::WriteOnly));
        QCOMPARE(output.write("retained final contents"), qint64(23));
    }
    std::optional<observation::Delivery> held;
    QVERIFY(wait_until([&] {
        auto delivery = channel->wait(20ms);
        if (delivery && delivery->batch.diagnostic.contains(QStringLiteral("Eligibility unavailable"))) {
            held = std::move(delivery);
            return true;
        }
        return false;
    }));
    QVERIFY(!subscription.covers_directory(root));
    const auto revision = subscription.coverage_revision(root);
    const auto previous_attempts = attempts.load();
    QVERIFY(wait_until([&] { return attempts.load() >= previous_attempts + 2; }));
    QCOMPARE(subscription.coverage_revision(root), revision);
    QVERIFY(subscription.rescan_required());
    if (lose_descendant) {
        QVERIFY(service.covered_logical_directories_for_tests().contains(healthy));
        QVERIFY(service.set_directory_available_for_tests(healthy, false));
        QVERIFY(wait_until([&] {
            return !service.covered_logical_directories_for_tests().contains(healthy) &&
                subscription.coverage_revision(root) > revision;
        }));
        QVERIFY(service.set_directory_available_for_tests(healthy, true));
        QVERIFY(wait_until([&] { return service.covered_logical_directories_for_tests().contains(healthy); }));
        QVERIFY(!subscription.covers_directory(root));
    }
    allow.store(true);
    QVERIFY(wait_until([&] { return subscription.covers_directory(root); }));
    QVERIFY(subscription.coverage_revision(root) > revision);
    held.reset();
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            QFile input(file);
            return input.open(QIODevice::ReadOnly) && input.readAll() == QByteArray("retained final contents") &&
                subscription.acknowledge(delivery->batch.capture);
        }
        return false;
    }));
    QVERIFY(!subscription.rescan_required());
}

void Filesystem_observation_scheduler_tests::explicit_recursive_alias_reconciles_without_following_descendant_links()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const QString first = workspace.filePath(QStringLiteral("first"));
    const QString second = workspace.filePath(QStringLiteral("second"));
    const QString excluded = workspace.filePath(QStringLiteral("excluded"));
    const QString alias = workspace.filePath(QStringLiteral("explicit-alias"));
    QVERIFY(QDir().mkpath(first + QStringLiteral("/nested")));
    QVERIFY(QDir().mkpath(second + QStringLiteral("/other")));
    QVERIFY(QDir().mkpath(excluded + QStringLiteral("/deeper")));
    QVERIFY(create_directory_alias(excluded, first + QStringLiteral("/automatic-link")));
    QVERIFY(create_directory_alias(first, alias));
    const auto remove_aliases = qScopeGuard([&] {
        remove_directory_alias(alias);
        remove_directory_alias(first + QStringLiteral("/automatic-link"));
    });
    const auto write = [](const QString& path, const QByteArray& bytes) {
        QFile file(path);
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(bytes) == bytes.size();
    };
    QVERIFY(write(first + QStringLiteral("/nested/file.txt"), "first"));
    QVERIFY(write(second + QStringLiteral("/other/file.txt"), "second"));

    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::RECURSIVE;
    options.interval = 100ms;
    options.directories = {{alias, 0}};
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    const auto initial_deadline = std::chrono::steady_clock::now() + 5s;
    auto initial = channel->wait(3s);
    QVERIFY(initial);
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(alias), 5000);
    const auto armed = service.covered_logical_directories_for_tests();
    QVERIFY(armed.contains(alias + QStringLiteral("/nested")));
    QVERIFY(!armed.contains(alias + QStringLiteral("/automatic-link")));
    QVERIFY(!armed.contains(excluded));
    observation::Batch acknowledged_initial_batch;
    for (;;) {
        QFile first_read(alias + QStringLiteral("/nested/file.txt"));
        QVERIFY(first_read.open(QIODevice::ReadOnly));
        QCOMPARE(first_read.readAll(), QByteArray("first"));
        first_read.close();
        if (subscription.acknowledge(initial->batch.capture)) {
            acknowledged_initial_batch = initial->batch;
            initial.reset();
            break;
        }
        initial.reset();
        const auto remaining = initial_deadline - std::chrono::steady_clock::now();
        QVERIFY(remaining > 0ms);
        initial = channel->wait(std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
        QVERIFY(initial);
    }

    QVERIFY(write(first + QStringLiteral("/nested/file.txt"), "changed"));
    const auto changed_deadline = std::chrono::steady_clock::now() + 3s;
    std::optional<observation::Batch> preceding_batch;
    std::optional<observation::Delivery> held;
    while (std::chrono::steady_clock::now() < changed_deadline) {
        const auto remaining = changed_deadline - std::chrono::steady_clock::now();
        held = channel->wait(std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
        if (!held || std::any_of(held->batch.events.cbegin(), held->batch.events.cend(), [&](const auto& event) {
                return event.path == alias + QStringLiteral("/nested/file.txt");
            }))
        {
            break;
        }
        for (const auto& directory : {alias, alias + QStringLiteral("/nested")}) {
            (void)QDir(directory).entryList(QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot);
        }
        QFile input(alias + QStringLiteral("/nested/file.txt"));
        QVERIFY(input.open(QIODevice::ReadOnly));
        QCOMPARE(input.readAll(), QByteArray("changed"));
        input.close();
        subscription.acknowledge(held->batch.capture);
        preceding_batch = held->batch;
        held.reset();
    }
    if (!held || !std::any_of(held->batch.events.cbegin(), held->batch.events.cend(), [&](const auto& event) {
            return event.path == alias + QStringLiteral("/nested/file.txt");
        }))
    {
        report_observation_batch(QStringLiteral("initial-acknowledged"), &acknowledged_initial_batch);
        if (preceding_batch) {
            report_observation_batch(QStringLiteral("preceding-alias-batch"), &*preceding_batch);
        }
        report_observation_batch(QStringLiteral("alias-held"), held ? &held->batch : nullptr);
        report_observation_state(QStringLiteral("alias-held-state"), service, subscription, alias);
    }
    QVERIFY(held);
    QVERIFY(std::any_of(held->batch.events.cbegin(), held->batch.events.cend(), [&](const auto& event) {
        return event.path == alias + QStringLiteral("/nested/file.txt");
    }));
    QVERIFY(remove_directory_alias(alias));
    QVERIFY(create_directory_alias(second, alias));
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(alias) &&
        service.covered_logical_directories_for_tests().contains(alias + QStringLiteral("/other")), 5000);
    QVERIFY(!service.covered_logical_directories_for_tests().contains(alias + QStringLiteral("/nested")));
    QVERIFY(!subscription.acknowledge(held->batch.capture));
    held.reset();
    auto replaced = channel->wait(3s);
    QVERIFY(replaced);
    QVERIFY(replaced->batch.rescan_required);
    QFile second_read(alias + QStringLiteral("/other/file.txt"));
    QVERIFY(second_read.open(QIODevice::ReadOnly));
    QCOMPARE(second_read.readAll(), QByteArray("second"));
    second_read.close();
    QVERIFY(subscription.acknowledge(replaced->batch.capture));
    replaced.reset();
    QVERIFY(!subscription.rescan_required());
    subscription.reset();
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().armed, 0, 5000);
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().scan_jobs, size_t(0), 5000);
}

#ifdef Q_OS_WIN
void Filesystem_observation_scheduler_tests::windows_discovery_settles_with_dangling_descendant_junction()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto target = workspace.filePath(QStringLiteral("target"));
    const auto root = workspace.filePath(QStringLiteral("explicit-alias"));
    const auto missing = workspace.filePath(QStringLiteral("removed"));
    const auto junction = target + QStringLiteral("/junction");
    const auto dangling = root + QStringLiteral("/junction");
    QVERIFY(QDir().mkpath(target + QStringLiteral("/ordinary")));
    QVERIFY(QDir().mkdir(missing));
    QVERIFY(create_directory_alias(target, root));
    const auto remove_aliases = qScopeGuard([&] {
        remove_directory_alias(root);
        remove_directory_alias(junction);
    });
    QVERIFY(create_directory_alias(missing, junction));
    QVERIFY(QDir().rmdir(missing));
    QVERIFY(QFileInfo(junction).isJunction());

    std::atomic_int junction_visits = 0;
    observation::detail::Direct_registry registry;
    const auto client = registry.attach([](const observation::Native_batch&) {});
    const auto release = qScopeGuard([&] { registry.detach(client); });
    registry.replace(client, {{root, 2}}, observation::Watch_mode::DISCOVERY_RECURSIVE,
        std::make_shared<vnm::path_name::Policy_epoch>(), [&](const QString&, const QString& path) {
            if (path == dangling) {
                ++junction_visits;
            }
            return true;
        }, false);
    QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, root) &&
        registry.covered_logical_directories_for_tests().contains(root + QStringLiteral("/ordinary")) &&
        registry.resource_counts().scan_pending == 0 && !registry.maintenance_pending_for_tests(), 5000);
    const auto expansions = registry.expansion_count_for_tests(client);
    const auto validations = observation::detail::native_test_hooks::windows_identity_validations.load();
    QTRY_VERIFY_WITH_TIMEOUT(
        observation::detail::native_test_hooks::windows_identity_validations.load() > validations, 5000);
    QCOMPARE(registry.expansion_count_for_tests(client), expansions);
    QCOMPARE(junction_visits.load(), 0);
    QVERIFY(!registry.covered_logical_directories_for_tests().contains(dangling));
}

void Filesystem_observation_scheduler_tests::windows_disjoint_retirement_preserves_healthy_capture()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto healthy = workspace.filePath(QStringLiteral("healthy/content"));
    QVERIFY(QDir().mkpath(healthy));
    const auto file_path = healthy + QStringLiteral("/document.txt");
    const auto write = [&](const QByteArray& bytes) {
        QFile file(file_path);
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(bytes) == bytes.size();
    };
    QVERIFY(write("initial"));
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DIRECT;
    options.interval = 20ms;
    options.directories = {{healthy, 0}};
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QTRY_VERIFY_WITH_TIMEOUT(subscription.covers_directory(healthy), 5000);
    const auto acquire = [&](const QByteArray& expected) {
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (std::chrono::steady_clock::now() < deadline) {
            auto delivery = channel->wait(20ms);
            if (!delivery) {
                continue;
            }
            QFile file(file_path);
            if (!file.open(QIODevice::ReadOnly) || file.readAll() != expected) {
                return false;
            }
            if (subscription.acknowledge(delivery->batch.capture)) {
                return true;
            }
        }
        return false;
    };
    QVERIFY(acquire("initial"));
    options.directories.clear();
    constexpr int k_other_anchors = 48;
    for (int index = 0; index != k_other_anchors; ++index) {
        const auto path = workspace.filePath(QStringLiteral("other-%1/content").arg(index));
        QVERIFY(QDir().mkpath(path));
        options.directories.append({path, 0});
    }
    auto other_channel = std::make_shared<observation::Wait_channel>();
    auto other = service.subscribe(options, other_channel);
    QTRY_VERIFY_WITH_TIMEOUT(std::all_of(options.directories.cbegin(), options.directories.cend(),
        [&](const auto& path) { return other.covers_directory(path.path); }), 5000);
    QCOMPARE(service.resource_counts().armed, k_other_anchors + 1);
    const auto bytes = service.resource_counts().native_bytes;
    QVERIFY(write("held acquisition"));
    auto held = channel->wait(3s);
    QVERIFY(held);
    QFile input(file_path);
    QVERIFY(input.open(QIODevice::ReadOnly));
    QCOMPARE(input.readAll(), QByteArray("held acquisition"));
    input.close();
    const auto revision = subscription.coverage_revision(healthy);
    observation::Native_watcher::set_windows_hold_retired_completions_for_tests(true);
    const auto release = qScopeGuard([] {
        observation::Native_watcher::set_windows_hold_retired_completions_for_tests(false);
    });
    other.reset();
    QTRY_COMPARE_WITH_TIMEOUT(observation::Native_watcher::windows_held_retirement_count_for_tests(),
        k_other_anchors, 5000);
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().retiring, k_other_anchors, 5000);
    QCOMPARE(service.resource_counts().native_bytes, bytes);
    QVERIFY(subscription.covers_directory(healthy));
    QCOMPARE(subscription.coverage_revision(healthy), revision);
    QVERIFY(subscription.acknowledge(held->batch.capture));
    held.reset();
    QVERIFY(write("progress during unrelated retirement"));
    QVERIFY(acquire("progress during unrelated retirement"));
    QCOMPARE(observation::Native_watcher::windows_held_retirement_count_for_tests(), k_other_anchors);
    observation::Native_watcher::set_windows_hold_retired_completions_for_tests(false);
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().retiring, 0, 5000);
    QVERIFY(service.resource_counts().native_bytes < bytes);
    subscription.reset();
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().native_bytes, size_t(0), 5000);
}

void Filesystem_observation_scheduler_tests::windows_disjoint_replacement_releases_obsolete_plan_memory()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto first = workspace.filePath(QStringLiteral("first/content"));
    const auto second = workspace.filePath(QStringLiteral("other/content"));
    QVERIFY(QDir().mkpath(first));
    QVERIFY(QDir().mkpath(second));
    const auto policy = std::make_shared<vnm::path_name::Policy_epoch>();
    const auto measure = [&](const QList<observation::Watch_spec>& paths) {
        observation::detail::Direct_registry registry;
        const auto client = registry.attach([](const observation::Native_batch&) {});
        const auto release = qScopeGuard([&] { registry.detach(client); });
        registry.replace(client, paths, observation::Watch_mode::DIRECT, policy, {}, true);
        if (!wait_until([&] {
            return std::all_of(paths.cbegin(), paths.cend(), [&](const auto& path) {
                return registry.covers(client, path.path);
            });
        })) {
            return size_t(0);
        }
        return registry.resource_counts().plan_bytes;
    };
    const auto first_bytes = measure({{first, 0}});
    const auto second_bytes = measure({{second, 0}});
    const auto combined_bytes = measure({{first, 0}, {second, 0}});
    QVERIFY(first_bytes != 0 && second_bytes != 0);
    const auto budget = std::max(first_bytes, second_bytes);
    QVERIFY(combined_bytes > budget);
    observation::detail::direct_limits_t limits;
    limits.plan_bytes = budget;
    observation::detail::Direct_registry registry(limits);
    const auto final_file = second + QStringLiteral("/final.txt");
    std::atomic_bool saw_final = false;
    const auto client = registry.attach([&](const observation::Native_batch& batch) {
        for (const auto& event : batch.events) {
            if (event.path == final_file) {
                saw_final.store(true);
            }
        }
    });
    const auto release = qScopeGuard([&] { registry.detach(client); });
    registry.replace(client, {{first, 0}}, observation::Watch_mode::DIRECT, policy, {}, true);
    QVERIFY(wait_until([&] { return registry.covers(client, first); }));
    registry.replace(client, {{second, 0}}, observation::Watch_mode::DIRECT, policy, {}, true);
    // Either final plan fits; retaining both obsolete and current identity
    // charges must not turn a constrained replacement into a permanent stall.
    QTRY_VERIFY_WITH_TIMEOUT(registry.covers(client, second), 5000);
    QVERIFY(!registry.covers(client, first));
    QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().desired, 1, 5000);
    QTRY_COMPARE_WITH_TIMEOUT(registry.resource_counts().retiring, 0, 5000);
    QVERIFY(registry.resource_counts().plan_bytes <= budget);
    {
        QFile file(final_file);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("final"), qint64(5));
    }
    QVERIFY(wait_until([&] { return saw_final.load(); }));
}

void Filesystem_observation_scheduler_tests::windows_ancestor_keeps_overlapping_interests_movable()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto original = workspace.filePath(QStringLiteral("checkout"));
    const auto moved = workspace.filePath(QStringLiteral("moved"));
    QVERIFY(QDir().mkpath(original + QStringLiteral("/nested/metadata")));
    const auto write = [](const QString& path, const QByteArray& bytes) {
        QFile file(path);
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate) && file.write(bytes) == bytes.size();
    };
    const auto relative = QStringLiteral("/nested/document.txt");
    QVERIFY(write(original + relative, "initial"));
    observation::Service service;
    auto recursive_channel = std::make_shared<observation::Wait_channel>();
    auto files_channel = std::make_shared<observation::Wait_channel>();
    auto exact_channel = std::make_shared<observation::Wait_channel>();
    auto metadata_channel = std::make_shared<observation::Wait_channel>();
    observation::Subscription_options options;
    options.interval = 20ms;
    options.directories = {{original, 0}};
    auto recursive = service.subscribe(options, recursive_channel);
    options.mode = observation::Watch_mode::DIRECT;
    options.directories = {{original + QStringLiteral("/nested"), 0}};
    auto files = service.subscribe(options, files_channel);
    options.directories.clear();
    options.exact_files = {original + relative};
    auto exact = service.subscribe(options, exact_channel);
    options.exact_files.clear();
    options.mode = observation::Watch_mode::RECURSIVE;
    options.directories = {{original + QStringLiteral("/nested/metadata"), 0}};
    auto metadata = service.subscribe(options, metadata_channel);
    QTRY_VERIFY_WITH_TIMEOUT(recursive.covers_directory(original) &&
        files.covers_directory(original + QStringLiteral("/nested")) &&
        exact.covers_directory(original + QStringLiteral("/nested")) &&
        metadata.covers_directory(original + QStringLiteral("/nested/metadata")), 5000);
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().scan_jobs, size_t(0), 5000);
    QCOMPARE(service.resource_counts().armed, 1);
    QCOMPARE(service.resource_counts().retiring, 0);
    QCOMPARE(service.armed_directories_for_tests(), QStringList{workspace.path()});

    const auto initial_deadline = std::chrono::steady_clock::now() + 3s;
    bool initial_acquired = false;
    while (!initial_acquired && std::chrono::steady_clock::now() < initial_deadline) {
        auto delivery = recursive_channel->wait(20ms);
        if (!delivery) {
            continue;
        }
        QFile file(original + relative);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), QByteArray("initial"));
        file.close();
        initial_acquired = recursive.acknowledge(delivery->batch.capture);
    }
    QVERIFY(initial_acquired);
    QVERIFY(write(original + relative, "held before move"));
    auto held = recursive_channel->wait(3s);
    QVERIFY(held);
    // All logical reasons remain installed during the sole filesystem move.
    QVERIFY(QDir().rename(original, moved));
    QTRY_VERIFY_WITH_TIMEOUT(!recursive.covers_directory(original) &&
        !files.covers_directory(original + QStringLiteral("/nested")) &&
        !exact.covers_directory(original + QStringLiteral("/nested")) &&
        !metadata.covers_directory(original + QStringLiteral("/nested/metadata")), 5000);
    QVERIFY(!recursive.acknowledge(held->batch.capture));
    held.reset();
    auto changed = recursive_channel->wait(3s);
    QVERIFY(changed && changed->batch.rescan_required);
    changed.reset();

    recursive.reset();
    files.reset();
    exact.reset();
    metadata.reset();
    options.directories = {{moved, 0}};
    recursive_channel = std::make_shared<observation::Wait_channel>();
    recursive = service.subscribe(options, recursive_channel);
    QTRY_VERIFY_WITH_TIMEOUT(recursive.covers_directory(moved), 5000);
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    bool acquired = false;
    while (!acquired && std::chrono::steady_clock::now() < deadline) {
        auto delivery = recursive_channel->wait(20ms);
        if (!delivery) {
            continue;
        }
        QFile file(moved + relative);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), QByteArray("held before move"));
        file.close();
        acquired = recursive.acknowledge(delivery->batch.capture);
    }
    QVERIFY(acquired);
    QVERIFY(write(moved + relative, "after move"));
    auto edited = recursive_channel->wait(3s);
    QVERIFY(edited);
    QVERIFY(std::any_of(edited->batch.events.cbegin(), edited->batch.events.cend(), [&](const auto& event) {
        return event.path == moved + relative && event.kind == observation::Event_kind::MODIFIED;
    }));
    QFile file(moved + relative);
    QVERIFY(file.open(QIODevice::ReadOnly));
    QCOMPARE(file.readAll(), QByteArray("after move"));
    file.close();
    QVERIFY(recursive.acknowledge(edited->batch.capture));
    edited.reset();
    recursive.reset();
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().armed, 0, 5000);
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().retiring, 0, 5000);
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().native_bytes, size_t(0), 5000);
}
#endif

void Filesystem_observation_scheduler_tests::sibling_rename_preserves_guarded_and_exact_captures()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const QString selected = workspace.filePath(QStringLiteral("selected"));
    const QString staged = workspace.filePath(QStringLiteral("staged"));
    const QString other = workspace.filePath(QStringLiteral("other"));
    QVERIFY(QDir().mkpath(selected));
    QVERIFY(QDir().mkpath(staged));
    QVERIFY(QDir().mkpath(other));
    const QString file = selected + QStringLiteral("/file.txt");
    const QString policy = workspace.filePath(QStringLiteral("policy.txt"));
    const auto write = [](const QString& path, const QByteArray& bytes) {
        QFile output(path);
        return output.open(QIODevice::WriteOnly | QIODevice::Truncate) && output.write(bytes) == bytes.size();
    };
    QVERIFY(write(file, "initial"));
    QVERIFY(write(policy, "policy"));
#ifdef Q_OS_MACOS
    QVERIFY(complete_native_fixture_setup(workspace.path()));
#endif
    observation::Service service;
    observation::Subscription_options options;
    options.directories = {{selected, 0}};
    options.interval = 20ms;
    auto selected_channel = std::make_shared<observation::Wait_channel>();
    auto selected_subscription = service.subscribe(options, selected_channel);
    options.mode = observation::Watch_mode::DIRECT;
    options.directories.clear();
    options.exact_files = {policy};
    auto policy_channel = std::make_shared<observation::Wait_channel>();
    auto policy_subscription = service.subscribe(options, policy_channel);
    options.exact_files.clear();
    options.directories = {{workspace.path(), 0}};
    auto parent_channel = std::make_shared<observation::Wait_channel>();
    auto parent_subscription = service.subscribe(options, parent_channel);
    QTRY_VERIFY_WITH_TIMEOUT(selected_subscription.covers_directory(selected) &&
        policy_subscription.covers_directory(workspace.path()) &&
        parent_subscription.covers_directory(workspace.path()), 5000);
    const auto acquire = [](auto& subscription, const auto& channel, const QString& path) {
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (std::chrono::steady_clock::now() < deadline) {
            auto delivery = channel->wait(20ms);
            if (!delivery) {
                continue;
            }
            QFile input(path);
            if (!input.open(QIODevice::ReadOnly) || input.readAll().isEmpty()) {
                return false;
            }
            if (subscription.acknowledge(delivery->batch.capture)) {
                return true;
            }
        }
        return false;
    };
    QVERIFY(acquire(selected_subscription, selected_channel, file));
    QVERIFY(acquire(policy_subscription, policy_channel, policy));
    QVERIFY(acquire(parent_subscription, parent_channel, policy));

    QVERIFY(write(file, "changed"));
    auto held = selected_channel->wait(3s);
    QVERIFY(held);
    QFile read(file);
    QVERIFY(read.open(QIODevice::ReadOnly));
    QCOMPARE(read.readAll(), QByteArray("changed"));
    read.close();
    QVERIFY(QDir().rename(staged, other + QStringLiteral("/newcomer")));
    bool parent_observed = false;
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!parent_observed && std::chrono::steady_clock::now() < deadline) {
        auto delivery = parent_channel->wait(20ms);
        if (delivery) {
            parent_observed = std::any_of(delivery->batch.events.cbegin(), delivery->batch.events.cend(),
                [&](const auto& event) {
                    return (event.kind == observation::Event_kind::RENAMED &&
                            (event.path == staged || event.old_path == staged)) ||
                        (event.kind == observation::Event_kind::REMOVED && event.path == staged);
                });
        }
    }
    QVERIFY(parent_observed);
    QVERIFY(selected_subscription.acknowledge(held->batch.capture));
    held.reset();
    const auto policy_delivery = policy_channel->wait(100ms);
    if (policy_delivery) {
        report_observation_batch(QStringLiteral("sibling-rename-policy"), &policy_delivery->batch);
    }
    QVERIFY(!policy_delivery);
    QVERIFY(!policy_subscription.rescan_required());

    // Moving the observed directory itself must still reject its held capture.
    QVERIFY(write(file, "before move"));
    held = selected_channel->wait(3s);
    QVERIFY(held);
    QVERIFY(QDir().rename(selected, other + QStringLiteral("/selected")));
    QTRY_VERIFY_WITH_TIMEOUT(!selected_subscription.covers_directory(selected), 5000);
    QVERIFY(!selected_subscription.acknowledge(held->batch.capture));
    held.reset();
    auto affected = selected_channel->wait(3s);
    QVERIFY(affected && affected->batch.rescan_required);

    // Retained unrelated detail does not narrow a genuine registration-wide loss.
    observation::Native_batch lost;
    lost.root = lost.scope = workspace.path();
    lost.rescan_required = true;
    lost.reason = observation::Native_reason::QUEUE_OVERFLOW;
    lost.events.append({staged, {}, observation::Event_kind::MODIFIED});
    service.ingest_for_tests(policy_subscription, lost);
    auto loss = policy_channel->wait(3s);
    QVERIFY(loss && loss->batch.rescan_required);
}

void Filesystem_observation_scheduler_tests::eligibility_replacement_preserves_capture_and_shared_reasons_data()
{
    QTest::addColumn<bool>("supersede_held_filter");
    QTest::newRow("replacement-at-capacity") << false;
    QTest::newRow("stale-filter-result") << true;
}

void Filesystem_observation_scheduler_tests::eligibility_replacement_preserves_capture_and_shared_reasons()
{
    QFETCH(bool, supersede_held_filter);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("root"));
    const auto previous = root + QStringLiteral("/previous");
    const auto replacement = root + QStringLiteral("/replacement");
    const auto shared = root + QStringLiteral("/shared");
    for (const auto& path : {previous, replacement, shared}) {
        QVERIFY(QDir().mkpath(path));
    }
    const auto write = [](const QString& path, const QByteArray& bytes) {
        QFile output(path);
        return output.open(QIODevice::WriteOnly) && output.write(bytes) == bytes.size();
    };
    QSemaphore entered;
    QSemaphore resume;
    std::atomic_bool pause = true;
    std::atomic_bool hook_timed_out = false;
    observation::limits_t limits;
#ifdef Q_OS_WIN
    limits.native_registrations = 1;
#else
    limits.native_registrations = 4;
#endif
    observation::Service service(limits);
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::RECURSIVE;
    options.directories = {{root, 0}};
    options.interval = 50ms;
    options.directory_filter = [replacement](const QString&, const QString& path) {
        return path != replacement;
    };
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    options.mode = observation::Watch_mode::DIRECT;
    options.directories = {{shared, 0}};
    options.directory_filter = {};
    auto independent_channel = std::make_shared<observation::Wait_channel>();
    auto independent = service.subscribe(options, independent_channel);
    const auto release = qScopeGuard([&] {
        resume.release();
        subscription.reset();
        independent.reset();
    });
    QVERIFY(wait_until([&] {
        return subscription.covers_directory(root) && independent.covers_directory(shared);
    }));
    auto held = channel->wait(3s);
    QVERIFY(held);
    const auto old_capture = held->batch.capture;
    while (auto initial = independent_channel->wait(150ms)) {
        independent.acknowledge(initial->batch.capture);
    }
    QVERIFY(subscription.replace_directory_filter([&](const QString&, const QString& path) {
        if (pause.exchange(false)) {
            entered.release();
            if (!resume.tryAcquire(1, 10000)) {
                hook_timed_out.store(true);
            }
        }
        return path != previous;
    }));
    QVERIFY(!subscription.acknowledge(old_capture));
    QVERIFY(entered.tryAcquire(1, 5000));
    QVERIFY(!subscription.covers_directory(root));
    QVERIFY(independent.covers_directory(shared));
    if (supersede_held_filter) {
        QVERIFY(subscription.replace_directory_filter([replacement](const QString&, const QString& path) {
            return path != replacement;
        }));
    }
    const auto independent_file = shared + QStringLiteral("/live.txt");
    QVERIFY(write(independent_file, "independent while planner held"));
    bool saw_independent = false;
    QVERIFY(wait_until([&] {
        if (auto delivery = independent_channel->wait(20ms)) {
            for (const auto& event : delivery->batch.events) {
                saw_independent |= event.path == independent_file;
            }
            independent.acknowledge(delivery->batch.capture);
        }
        return saw_independent;
    }));
    QVERIFY(!channel->wait(20ms));
    resume.release();
    QVERIFY(wait_until([&] { return subscription.covers_directory(root); }));
    QVERIFY(!hook_timed_out.load());
#ifdef Q_OS_WIN
    QCOMPARE(service.resource_counts().desired, 1);
    QCOMPARE(service.resource_counts().armed, 1);
#else
    QCOMPARE(service.resource_counts().desired, 4);
    QCOMPARE(service.resource_counts().armed, 4);
#endif
    QVERIFY(independent.covers_directory(shared));
    held.reset();
    const auto final_file = (supersede_held_filter ? previous : replacement) + QStringLiteral("/final.txt");
    QVERIFY(write(final_file, "final accepted generation"));
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            QFile input(final_file);
            const bool acquired = input.open(QIODevice::ReadOnly) &&
                input.readAll() == QByteArray("final accepted generation");
            return delivery->batch.rescan_required && acquired &&
                subscription.acknowledge(delivery->batch.capture);
        }
        return false;
    }));
    QVERIFY(!subscription.rescan_required());
    QVERIFY(write(final_file, "detail after reconciliation"));
    bool saw_final = false;
    QVERIFY(wait_until([&] {
        if (auto delivery = channel->wait(20ms)) {
            for (const auto& event : delivery->batch.events) {
                saw_final |= event.path == final_file;
            }
            QFile input(final_file);
            const bool acquired = input.open(QIODevice::ReadOnly) &&
                input.readAll() == QByteArray("detail after reconciliation");
            return saw_final && acquired && subscription.acknowledge(delivery->batch.capture);
        }
        return false;
    }));
    QVERIFY(!subscription.rescan_required());
}

void Filesystem_observation_scheduler_tests::direct_sharing_preserves_independent_capture_and_retirement()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    const auto root = workspace.filePath(QStringLiteral("content"));
    QVERIFY(QDir().mkpath(root));
    const auto file = root + QStringLiteral("/settings.ini");
    const auto write = [&] (const QByteArray& bytes) {
        QFile output(file);
        return output.open(QIODevice::WriteOnly) && output.write(bytes) == bytes.size();
    };
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DIRECT;
    options.interval = 50ms;
    options.directories = {{root, 0}};
    auto first_channel = std::make_shared<observation::Wait_channel>();
    auto first = service.subscribe(options, first_channel);
    QVERIFY(wait_until([&] { return first.covers_directory(root); }));
    auto initial = first_channel->wait(3s);
    QVERIFY(initial);
    first.acknowledge(initial->batch.capture);
    initial.reset();

    options.directories.clear();
    options.exact_files = {file};
    options.interval = 100ms;
    auto exact_channel = std::make_shared<observation::Wait_channel>();
    auto exact = service.subscribe(options, exact_channel);
    auto late = exact_channel->wait(3s);
    QVERIFY(late && late->batch.rescan_required);
    QVERIFY(exact.covers_directory(root));
#ifdef Q_OS_WIN
    QCOMPARE(service.resource_counts().desired, 1);
#else
    QCOMPARE(service.resource_counts().desired, 2);
#endif
    QVERIFY(exact.acknowledge(late->batch.capture));
    late.reset();
    while (auto delivery = first_channel->wait(150ms)) {
        first.acknowledge(delivery->batch.capture);
    }
    while (auto delivery = exact_channel->wait(150ms)) {
        exact.acknowledge(delivery->batch.capture);
    }
    QVERIFY(write("leading"));
    auto held = first_channel->wait(3s);
    auto leading = exact_channel->wait(3s);
    QVERIFY(held && leading);
    QVERIFY(!exact.acknowledge(held->batch.capture));
    QVERIFY(exact.acknowledge(leading->batch.capture));
    leading.reset();
    QVERIFY(write("final contents while another receiver is held"));
    auto final = exact_channel->wait(3s);
    QVERIFY(final);
    QVERIFY(std::any_of(final->batch.events.cbegin(), final->batch.events.cend(),
        [&](const auto& event) { return event.path == file; }));
    QVERIFY(exact.acknowledge(final->batch.capture));
    final.reset();
    QVERIFY(!first_channel->wait(20ms));
    first.reset();
    held.reset();
    QVERIFY(wait_until([&] { return service.statistics().subscriptions == 1; }));
#ifdef Q_OS_WIN
    QCOMPARE(service.resource_counts().desired, 1);
#else
    QCOMPARE(service.resource_counts().desired, 2);
#endif
    QVERIFY(exact.covers_directory(root));
    QVERIFY(write("edit after independent cancellation"));
    auto survived = exact_channel->wait(3s);
    QVERIFY(survived);
    QVERIFY(std::any_of(survived->batch.events.cbegin(), survived->batch.events.cend(),
        [&](const auto& event) { return event.path == file; }));
}

void Filesystem_observation_scheduler_tests::direct_budget_failure_recovers_after_last_user_retires_data()
{
    QTest::addColumn<bool>("queued_detail");
    QTest::newRow("ordinary-recovery")          << false;
    QTest::newRow("queued-pre-recovery-detail") << true;
}

void Filesystem_observation_scheduler_tests::direct_budget_failure_recovers_after_last_user_retires()
{
    QFETCH(bool, queued_detail);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
#ifdef Q_OS_WIN
    // Distinct, non-overlapping ancestors actually compete for one native slot.
    const auto first_path = workspace.filePath(QStringLiteral("first/content"));
    const auto waiting_path = workspace.filePath(QStringLiteral("waiting/content"));
#else
    const auto first_path = workspace.filePath(QStringLiteral("first"));
    const auto waiting_path = workspace.filePath(QStringLiteral("waiting"));
#endif
    QVERIFY(QDir().mkpath(first_path));
    QVERIFY(QDir().mkpath(waiting_path));
    observation::limits_t limits;
#ifdef Q_OS_WIN
    limits.native_registrations = 1;
#else
    limits.native_registrations = 2;
#endif
    observation::Service service(limits);
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DIRECT;
    options.interval = 20ms;
    options.directories = {{first_path, 0}};
    auto first_channel = std::make_shared<observation::Wait_channel>();
    auto first = service.subscribe(options, first_channel);
    QVERIFY(wait_until([&] { return first.covers_directory(first_path); }));
    options.directories = {{waiting_path, 0}};
    auto waiting_channel = std::make_shared<observation::Wait_channel>();
    auto waiting = service.subscribe(options, waiting_channel);
    auto incomplete = waiting_channel->wait(3s);
    QVERIFY(incomplete && incomplete->batch.rescan_required);
    const auto incomplete_batch = incomplete->batch;
    QVERIFY(!waiting.covers_directory(waiting_path));
    QVERIFY(waiting.rescan_required());
    const auto revision = waiting.coverage_revision(waiting_path);
    QVERIFY(revision != 0);
#ifdef Q_OS_WIN
    QCOMPARE(service.resource_counts().desired, 2);
    QCOMPARE(service.resource_counts().armed, 1);
#else
    QCOMPARE(service.resource_counts().desired, 3);
    QCOMPARE(service.resource_counts().armed, 2);
#endif
    QCOMPARE(service.resource_counts().failed, 1);
    incomplete.reset();
    if (queued_detail) {
        // Late setup detail carries the unacknowledged failure until recovery.
        observation::Native_batch detail;
        detail.root = detail.scope = waiting_path;
        detail.coverage_revision = revision;
        detail.events.append({waiting_path, {}, observation::Event_kind::CREATED,
            observation::Entry_type::DIRECTORY});
        service.ingest_for_tests(waiting, detail);
        QVERIFY(wait_until([&] { return service.statistics().outstanding == 2; }));
    }
    first.reset();
    QVERIFY(wait_until([&] { return waiting.covers_directory(waiting_path); }));
    QVERIFY(waiting.coverage_revision(waiting_path) > revision);
    // Native coverage may recover while an older capture is still queued.
    std::optional<observation::Delivery> recovered;
    bool skipped_incomplete_capture = false;
    const bool received_recovery = wait_until([&] {
        auto delivery = waiting_channel->wait(20ms);
        if (!delivery) {
            return false;
        }
        if (delivery->batch.capture.coverage_sequence <= incomplete_batch.capture.coverage_sequence) {
            skipped_incomplete_capture = true;
            return false;
        }
        recovered = std::move(delivery);
        return true;
    });
    if (!received_recovery || !recovered->batch.rescan_required) {
        report_observation_batch(QStringLiteral("budget-incomplete"), &incomplete_batch);
        report_observation_batch(QStringLiteral("budget-recovered"), recovered ? &recovered->batch : nullptr);
        report_observation_state(QStringLiteral("budget-recovery-missing"), service, waiting, waiting_path);
    }
    QVERIFY(recovered && recovered->batch.rescan_required);
    QVERIFY(!queued_detail || skipped_incomplete_capture);
    const bool acknowledged = waiting.acknowledge(recovered->batch.capture);
    if (!acknowledged) {
        report_observation_batch(QStringLiteral("budget-incomplete"), &incomplete_batch);
        report_observation_batch(QStringLiteral("budget-recovered"), &recovered->batch);
        report_observation_state(QStringLiteral("budget-recovery-acknowledgement"), service, waiting, waiting_path);
    }
    QVERIFY(acknowledged);
#ifdef Q_OS_WIN
    QCOMPARE(service.resource_counts().desired, 1);
    QCOMPARE(service.resource_counts().armed, 1);
#else
    QCOMPARE(service.resource_counts().desired, 2);
    QCOMPARE(service.resource_counts().armed, 2);
#endif
    QCOMPARE(service.resource_counts().failed, 0);
}

#ifdef Q_OS_LINUX
void Filesystem_observation_scheduler_tests::direct_wake_exhaustion_recovers_without_replacing_interest()
{
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    observation::Native_watcher::set_linux_wake_error_for_tests(true);
    const auto restore = qScopeGuard([] {
        observation::Native_watcher::set_linux_wake_error_for_tests(false);
    });
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DIRECT;
    options.directories = {{workspace.path(), 0}};
    options.interval = 20ms;
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    auto incomplete = channel->wait(3s);
    QVERIFY(incomplete && incomplete->batch.rescan_required);
    QVERIFY(incomplete->batch.diagnostic.contains(QStringLiteral("wake descriptor unavailable")));
    QVERIFY(!subscription.covers_directory(workspace.path()));
    QCOMPARE(service.resource_counts().armed, 0);
    QCOMPARE(service.resource_counts().failed, 2);
    const auto revision = subscription.coverage_revision(workspace.path());
    incomplete.reset();
    observation::Native_watcher::set_linux_wake_error_for_tests(false);
    QVERIFY(wait_until([&] { return subscription.covers_directory(workspace.path()); }));
    QVERIFY(subscription.coverage_revision(workspace.path()) > revision);
    auto recovered = channel->wait(3s);
    QVERIFY(recovered && recovered->batch.rescan_required);
    QVERIFY(subscription.acknowledge(recovered->batch.capture));
    QCOMPARE(service.resource_counts().armed, 2);
    QCOMPARE(service.resource_counts().failed, 0);
}
#endif

void Filesystem_observation_scheduler_tests::late_native_subscriber_receives_its_own_reconciliation_data()
{
    QTest::addColumn<bool>("covered");
    QTest::newRow("armed") << true;
    QTest::newRow("incomplete") << false;
}

void Filesystem_observation_scheduler_tests::late_native_subscriber_receives_its_own_reconciliation()
{
    QFETCH(bool, covered);
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
#ifdef Q_OS_MACOS
    QVERIFY(complete_native_fixture_setup(directory.path()));
#endif
    observation::Service service;
    service.use_manual_clock_for_tests();
    observation::Subscription_options options;
    options.directories.append({directory.path(), 0});
    options.classifier = [](const observation::Event&) { return false; };
    auto first_channel = std::make_shared<observation::Wait_channel>();
    auto first = service.subscribe(options, first_channel);
    auto armed = first_channel->wait(3s);
    QVERIFY(armed && armed->batch.rescan_required);
    QVERIFY(first.covers_directory(directory.path()));
    auto first_capture = armed->batch.capture;
    QVERIFY(first.acknowledge(first_capture));
    armed.reset();
    QVERIFY(!first.rescan_required());
    service.advance_clock_for_tests(options.interval);

    if (!covered) {
        first.set_coverage_for_tests(directory.path(), false);
        QCOMPARE(first.coverage_status(directory.path()).state, observation::Coverage_state::FAILED);
        QCOMPARE(first.coverage_status(directory.path()).diagnostic,
            QStringLiteral("Injected directory coverage loss"));
        auto loss = first_channel->wait(3s);
        QVERIFY(loss && loss->batch.rescan_required);
        QVERIFY(!loss->batch.all_interests);
        QCOMPARE(loss->batch.scopes, QStringList{directory.path()});
        QVERIFY(loss->batch.events.isEmpty());
        QCOMPARE(loss->batch.diagnostic, QStringLiteral("Injected directory coverage loss"));
        QCOMPARE(loss->batch.capture.subscription_id, first_capture.subscription_id);
        QCOMPARE(loss->batch.capture.generation, first_capture.generation);
        QVERIFY(loss->batch.capture.event_sequence > first_capture.event_sequence);
        QVERIFY(loss->batch.capture.coverage_sequence > first_capture.coverage_sequence);
        QCOMPARE(first.coverage_status(directory.path()).state, observation::Coverage_state::FAILED);
        QVERIFY(first.rescan_required());
        QVERIFY(!first.acknowledge(first_capture));
        QVERIFY(first.acknowledge(loss->batch.capture));
        first_capture = loss->batch.capture;
        loss.reset();
        QVERIFY(!first.rescan_required());
    }
    const auto revision = first.coverage_revision(directory.path());
    QVERIFY(revision != 0);
    const auto resources = service.resource_counts();
    const auto registration_attempts =
        observation::Native_watcher::registration_attempt_count_for_tests();

    // No file traffic follows arming. A new subscriber must reconcile even when
    // another subscriber already acknowledged this shared native registration.
    auto late_channel = std::make_shared<observation::Wait_channel>();
    auto late = service.subscribe(options, late_channel);
    auto initial = late_channel->wait(3s);
    QVERIFY2(initial, "Late subscriber received no initial reconciliation without file traffic");
    QVERIFY(initial->batch.rescan_required);
    QVERIFY(!initial->batch.all_interests);
    QCOMPARE(initial->batch.scopes, QStringList{directory.path()});
    QVERIFY(initial->batch.events.isEmpty());
    QVERIFY(initial->batch.capture.coverage_sequence != 0);
    QCOMPARE(late.covers_directory(directory.path()), covered);
    QCOMPARE(late.coverage_status(directory.path()).state,
        covered ? observation::Coverage_state::COVERED : observation::Coverage_state::FAILED);
    QCOMPARE(late.coverage_revision(directory.path()), revision);
    QCOMPARE(initial->batch.diagnostic, covered
        ? QStringLiteral("Observation coverage armed; reconciliation required")
        : QStringLiteral("Observation coverage incomplete; reconciliation required"));
    QVERIFY(!late.acknowledge(first_capture));
    QVERIFY(!first.acknowledge(initial->batch.capture));
    QVERIFY(late.rescan_required());
    QVERIFY(late.acknowledge(initial->batch.capture));
    QVERIFY(!late.rescan_required());
    initial.reset();
    QVERIFY(wait_until([&] { return service.statistics().outstanding == 0; }));

    service.advance_clock_for_tests(options.interval);
    QVERIFY(!first_channel->wait(20ms));
    QVERIFY(!late_channel->wait(20ms));
    QVERIFY(!first.rescan_required());
    QCOMPARE(first.coverage_revision(directory.path()), revision);
    QCOMPARE(service.resource_counts().desired, resources.desired);
    QCOMPARE(service.resource_counts().native_threads, resources.native_threads);
    QCOMPARE(observation::Native_watcher::registration_attempt_count_for_tests(), registration_attempts);
    late.reset();
    QCOMPARE(service.statistics().subscriptions, size_t(1));
    QCOMPARE(service.resource_counts().desired, resources.desired);
}

void Filesystem_observation_scheduler_tests::typed_settings()
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("settings.ini")), QSettings::IniFormat);
    const auto defaults = observation::Configuration::from_settings(settings);
    QCOMPARE(defaults.general_interval, 4000ms);
    QCOMPARE(defaults.document_interval, 2000ms);
    settings.setValue(QStringLiteral("observation/general_interval_ms"), 1500);
    QCOMPARE(observation::Configuration::from_settings(settings).general_interval, 1500ms);
    settings.setValue(QStringLiteral("observation/document_interval_ms"), -1);
    QVERIFY_EXCEPTION_THROWN(observation::Configuration::from_settings(settings), std::invalid_argument);
}

void Filesystem_observation_scheduler_tests::unrelated_groups_do_not_multiply_policy_queries()
{
    QTemporaryDir first_root;
    QTemporaryDir second_root;
    QVERIFY(first_root.isValid() && second_root.isValid());
    QVERIFY(QDir().mkpath(first_root.filePath(QStringLiteral("repository"))));
    QVERIFY(QDir().mkpath(second_root.filePath(QStringLiteral("repository"))));
    std::atomic_int queries{0};
    auto source = std::make_shared<vnm::path_name::Policy_epoch>([&](const QString&) {
        ++queries;
        return vnm::path_name::Directory_case_sensitivity::SENSITIVE;
    });
    observation::Service service;
    observation::Subscription_options options;
    options.policy_epoch = source;
    options.directories.append({first_root.filePath(QStringLiteral("repository")), 0});
    auto first = service.subscribe(options, std::make_shared<observation::Wait_channel>());
    const int first_queries = queries.load();
    options.directories.front().path = second_root.filePath(QStringLiteral("repository"));
    auto second = service.subscribe(options, std::make_shared<observation::Wait_channel>());
    QCOMPARE(queries.load(), 2 * first_queries);
}

void Filesystem_observation_scheduler_tests::coverage_reads_do_not_scan_unrelated_interests_data()
{
    QTest::addColumn<int>("interest_count");
    QTest::addColumn<bool>("case_sensitive");
    QTest::newRow("one-sensitive") << 1 << true;
    QTest::newRow("many-sensitive") << 64 << true;
    QTest::newRow("one-insensitive") << 1 << false;
    QTest::newRow("many-insensitive") << 64 << false;
}

void Filesystem_observation_scheduler_tests::coverage_reads_do_not_scan_unrelated_interests()
{
    namespace paths = vnm::path_name;
    namespace hooks = observation::detail::native_test_hooks;
    QFETCH(int, interest_count);
    QFETCH(bool, case_sensitive);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    std::atomic_int policy_queries = 0;
    auto policy = std::make_shared<paths::Policy_epoch>([&](const QString&) {
        ++policy_queries;
        return case_sensitive ? paths::Directory_case_sensitivity::SENSITIVE
                              : paths::Directory_case_sensitivity::INSENSITIVE;
    });
    observation::Service service;
    observation::Subscription_options options;
    options.mode = observation::Watch_mode::DIRECT;
    options.policy_epoch = policy;
    for (int index = 0; index < interest_count; ++index) {
        const auto path = workspace.filePath(QStringLiteral("Checkout-%1").arg(index));
        QVERIFY(QDir().mkpath(path));
        options.directories.append({path, 0});
    }
    auto subscription = service.subscribe(options, std::make_shared<observation::Wait_channel>());
    const auto all_covered = [&] {
        return std::all_of(options.directories.cbegin(), options.directories.cend(), [&](const auto& directory) {
            return subscription.covers_directory(directory.path);
        });
    };
    QTRY_VERIFY_WITH_TIMEOUT(all_covered(), 5000);
    const auto queries_before = policy_queries.load();
    const auto candidates_before = hooks::coverage_read_candidates;
    for (const auto& directory : options.directories) {
        const auto revision = subscription.coverage_revision(directory.path);
        QVERIFY(revision != 0);
        QCOMPARE(subscription.coverage_status(directory.path).state, observation::Coverage_state::COVERED);
        QVERIFY(subscription.covers_directory(directory.path));
        const auto normalized_alias = directory.path + QStringLiteral("/./");
        QCOMPARE(subscription.coverage_revision(normalized_alias), revision);
        QCOMPARE(subscription.coverage_status(normalized_alias).state, observation::Coverage_state::COVERED);
        QVERIFY(subscription.covers_directory(normalized_alias));
    }
    // Six reads per interest, with at most its own candidate in each of the
    // subscription and native registry. Unrelated interests must not add work.
    QVERIFY(hooks::coverage_read_candidates - candidates_before <= uint64_t(12 * interest_count));
    const auto original = options.directories.front().path;
    const auto alternate = workspace.filePath(QStringLiteral("checkout-0"));
    QCOMPARE(subscription.covers_directory(alternate), !case_sensitive);
    QCOMPARE(subscription.coverage_status(alternate).state, case_sensitive
        ? observation::Coverage_state::FAILED : observation::Coverage_state::COVERED);
    QCOMPARE(subscription.coverage_revision(alternate), case_sensitive
        ? uint64_t(0) : subscription.coverage_revision(original));
    const auto descendant = original + QStringLiteral("/unregistered-child");
    QVERIFY(!subscription.covers_directory(descendant));
    QCOMPARE(subscription.coverage_status(descendant).state, observation::Coverage_state::FAILED);
    QCOMPARE(subscription.coverage_revision(descendant), uint64_t(0));
    QCOMPARE(policy_queries.load(), queries_before);
    subscription.reset();
    QCOMPARE(subscription.coverage_status(original).state, observation::Coverage_state::FAILED);
    QCOMPARE(subscription.coverage_revision(original), uint64_t(0));
}

void Filesystem_observation_scheduler_tests::combined_directory_and_exact_file_interests()
{
    QTemporaryDir repository;
    QTemporaryDir metadata;
    QVERIFY(repository.isValid() && metadata.isValid());
    observation::Service service;
    observation::Subscription_options options;
    options.directories.append({repository.path(), 0});
    const auto metadata_file = metadata.filePath(QStringLiteral("HEAD"));
    options.exact_files.append(metadata_file);
    options.interval = 1ms;
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QVERIFY(wait_until([&] {
        return subscription.covers_directory(repository.path()) &&
            subscription.covers_directory(metadata.path());
    }));
    for (int count = 0; count < 8; ++count) {
        auto initial = channel->wait(50ms);
        if (!initial) break;
        subscription.acknowledge(initial->batch.capture);
    }
    QVERIFY(!subscription.rescan_required());
    const auto inject = [&](const QString& root, const QString& path, const QString& old_path = {}) {
        observation::Native_batch batch;
        batch.root = root;
        batch.scope = root;
        batch.coverage_revision = subscription.coverage_revision(root);
        batch.events.append({path, old_path, old_path.isEmpty()
            ? observation::Event_kind::MODIFIED : observation::Event_kind::RENAMED});
        service.ingest_for_tests(subscription, batch);
    };
    const auto tracked = repository.filePath(QStringLiteral("tracked.txt"));
    inject(repository.path(), tracked);
    auto repository_change = channel->wait(1s);
    QVERIFY(repository_change);
    QCOMPARE(repository_change->batch.events.front().path, tracked);
    repository_change.reset();

    // A parent registration required for an exact file is physical coverage, not
    // a request to classify every sibling as relevant.
    inject(metadata.path(), metadata.filePath(QStringLiteral("unrelated")));
    QVERIFY(!channel->wait(50ms));
    inject(metadata.path(), metadata_file);
    auto metadata_change = channel->wait(1s);
    QVERIFY(metadata_change);
    QCOMPARE(metadata_change->batch.events.front().path, metadata_file);
    metadata_change.reset();
    inject(metadata.path(), metadata.filePath(QStringLiteral("moved_HEAD")), metadata_file);
    auto rename = channel->wait(1s);
    QVERIFY(rename);
    QCOMPARE(rename->batch.events.front().old_path, metadata_file);
}

void Filesystem_observation_scheduler_tests::event_descendants_do_not_extend_policy_history()
{
    QTemporaryDir root;
    QVERIFY(root.isValid());
    std::atomic_int queries{0};
    auto policy = std::make_shared<vnm::path_name::Policy_epoch>([&](const QString&) {
        ++queries;
        return vnm::path_name::Directory_case_sensitivity::SENSITIVE;
    });
    observation::Service service;
    observation::Subscription_options options;
    options.directories.append({root.path(), 0});
    options.policy_epoch = policy;
    options.interval = 1ms;
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QVERIFY(wait_until([&] { return subscription.covers_directory(root.path()); }));
    for (int count = 0; count < 8; ++count) {
        auto initial = channel->wait(50ms);
        if (!initial) break;
        subscription.acknowledge(initial->batch.capture);
    }
    QVERIFY(!subscription.rescan_required());
    const int initial_queries = queries.load();
    for (int index = 0; index < 32; ++index) {
        observation::Native_batch batch;
        batch.root = root.path();
        batch.scope = root.path();
        batch.coverage_revision = subscription.coverage_revision(root.path());
        batch.events.append({root.filePath(QStringLiteral("generated-%1/inner/file.txt").arg(index)),
            {}, observation::Event_kind::MODIFIED});
        service.ingest_for_tests(subscription, batch);
        auto delivery = channel->wait(1s);
        QVERIFY(delivery);
    }
    QCOMPARE(queries.load(), initial_queries);
}

void Filesystem_observation_scheduler_tests::named_policy_forks_preserve_captured_modes()
{
    namespace paths = vnm::path_name;
    using Sensitivity = paths::Directory_case_sensitivity;
#ifdef Q_OS_WIN
    const QString root = QStringLiteral("C:/Parent/Repo");
#else
    const QString root = QStringLiteral("/Parent/Repo");
#endif
    std::atomic<Sensitivity> answer{Sensitivity::INSENSITIVE};
    std::atomic_int queries{0};
    paths::Policy_epoch source([&](const QString&) {
        ++queries;
        return answer.load();
    });
    auto retained = source.fork_for_paths({root}, 1024);
    QVERIFY(retained);
    const auto retained_key = retained->key(root);
    const int captured_queries = queries.load();
    answer.store(Sensitivity::UNKNOWN);
    auto alias = source.fork_for_paths({root.toLower()}, 1024, retained.get());
    QVERIFY(alias);
    QVERIFY(alias->key(root.toLower()) == retained_key);
    QCOMPARE(queries.load(), captured_queries);
    QCOMPARE(source.cache_usage().entries, size_t(0));
    QVERIFY(paths::matches_key(root.toLower(), retained_key));
    QVERIFY(paths::is_within_key(root.toLower() + QStringLiteral("/generated/child"), retained_key));
    QVERIFY(paths::is_ancestor_of_key(root.left(root.lastIndexOf(QLatin1Char('/'))), retained_key));

    const auto unknown_key = source.key(root);
    auto conflict = source.fork_for_paths({root}, 1024, retained.get());
    QVERIFY(!conflict);
    auto sticky = source.fork_for_paths({root}, 1024);
    QVERIFY(sticky);
    answer.store(Sensitivity::INSENSITIVE);
    QVERIFY(sticky->key(root) == unknown_key);
    QVERIFY(!paths::matches_key(root.toLower(), unknown_key));
    paths::Policy_epoch mixed([](const QString& parent) {
        return parent.endsWith(QStringLiteral("Parent"))
            ? Sensitivity::SENSITIVE : Sensitivity::INSENSITIVE;
    });
    const auto mixed_key = mixed.key(root);
    QVERIFY(paths::matches_key(root, mixed_key));
    QVERIFY(!paths::matches_key(root.left(root.lastIndexOf(QLatin1Char('/'))) +
        QStringLiteral("/repo"), mixed_key));
    QVERIFY(paths::matches_key(QString(root).replace(QStringLiteral("Parent"),
        QStringLiteral("parent")), mixed_key));
}

void Filesystem_observation_scheduler_tests::native_path_policy_matches_directory_case_sensitivity()
{
    namespace paths = vnm::path_name;
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    const QDir root(QFileInfo(temporary.path()).canonicalFilePath());
    const QString original = root.filePath(QStringLiteral("MixedCase"));
    const QString alternate = root.filePath(QStringLiteral("mixedcase"));
    QVERIFY(root.mkdir(QStringLiteral("MixedCase")));
    const bool case_insensitive = QFileInfo::exists(alternate);
    paths::Policy_epoch policy;
    QCOMPARE(policy.same(original, alternate), case_insensitive);
    QCOMPARE(policy.key(original) == policy.key(alternate), case_insensitive);
    QCOMPARE(policy.is_within(alternate + QStringLiteral("/child"), original), case_insensitive);
    if (!case_insensitive) {
        QVERIFY(root.mkdir(QStringLiteral("mixedcase")));
        QVERIFY(!policy.same(original, alternate));
    }
}

void Filesystem_observation_scheduler_tests::policy_history_retires_with_subscriptions()
{
    namespace paths = vnm::path_name;
    QTemporaryDir root;
    QVERIFY(root.isValid());
    std::atomic<paths::Directory_case_sensitivity> answer{paths::Directory_case_sensitivity::INSENSITIVE};
    auto supplied = std::make_shared<paths::Policy_epoch>([&](const QString&) { return answer.load(); });
    observation::Service service;
    observation::Subscription_options options;
    options.directories.append({root.path(), 0});
    options.policy_epoch = supplied;
    auto channel = std::make_shared<observation::Wait_channel>();
    auto subscription = service.subscribe(options, channel);
    QVERIFY(wait_until([&] { return subscription.covers_directory(root.path()); }));
    const auto resources = service.resource_counts();
    answer.store(paths::Directory_case_sensitivity::UNKNOWN);
    options.directories.front().path = root.path().toUpper();
    auto second_channel = std::make_shared<observation::Wait_channel>();
    auto second = service.subscribe(options, second_channel);
    QVERIFY(second.covers_directory(options.directories.front().path));
    QCOMPARE(service.resource_counts().desired, resources.desired);
    QCOMPARE(service.resource_counts().native_threads, resources.native_threads);
    QCOMPARE(supplied->cache_usage().entries, size_t(0));
    const auto initial = service.statistics();
    for (int index = 0; index < 128; ++index) {
        const auto path = root.filePath(QStringLiteral("unregistered-%1/nested").arg(index));
        QVERIFY(!subscription.covers_directory(path));
        QCOMPARE(subscription.coverage_revision(path), uint64_t(0));
    }
    QCOMPARE(service.statistics().policy_cache_entries, initial.policy_cache_entries);
    QCOMPARE(service.statistics().policy_cache_characters, initial.policy_cache_characters);
    subscription.reset();
    second.reset();
    QVERIFY(wait_until([&] {
        const auto stats = service.statistics();
        return stats.retiring_groups == 0 && stats.pending_registrations == 0;
    }));
    QCOMPARE(service.statistics().policy_cache_entries, size_t(0));
    QCOMPARE(service.statistics().policy_cache_characters, size_t(0));
    for (int index = 0; index < 32; ++index) {
        options.directories.front().path = root.filePath(QStringLiteral("generation-%1").arg(index));
        auto next = service.subscribe(options, std::make_shared<observation::Wait_channel>());
        next.reset();
    }
    QVERIFY(wait_until([&] { return service.statistics().retiring_groups == 0; }));
    QCOMPARE(supplied->cache_usage().entries, size_t(0));
    QCOMPARE(service.statistics().policy_cache_characters, size_t(0));

    // The implicit source factory must likewise retain no retired interests.
    options.policy_epoch.reset();
    for (int index = 0; index < 32; ++index) {
        options.directories.front().path = root.filePath(QStringLiteral("default-%1").arg(index));
        auto next = service.subscribe(options, std::make_shared<observation::Wait_channel>());
        next.reset();
    }
    QVERIFY(wait_until([&] { return service.statistics().retiring_groups == 0; }));
    QCOMPARE(service.statistics().policy_cache_characters, size_t(0));
}

void Filesystem_observation_scheduler_tests::policy_prefix_budget_rejects_without_source_mutation()
{
    namespace paths = vnm::path_name;
    std::atomic_int queries{0};
    auto supplied = std::make_shared<paths::Policy_epoch>([&](const QString&) {
        ++queries;
        return paths::Directory_case_sensitivity::SENSITIVE;
    });
    QString deep = QStringLiteral("/");
    for (int index = 0; index < 40; ++index) deep += QStringLiteral("a/");
    deep += QStringLiteral("file");
    QVERIFY(deep.size() < 256);
    QVERIFY_EXCEPTION_THROWN(supplied->fork_for_paths({deep}, 256), std::invalid_argument);
    QCOMPARE(queries.load(), 0);
    QCOMPARE(supplied->cache_usage().characters, size_t(0));
    observation::limits_t limits;
    limits.interest_characters = 16;
    observation::Service service(limits);
    observation::Subscription_options options;
    options.policy_epoch = supplied;
    options.exact_files.append(QStringLiteral("/exceeds-observation-interest-budget/file"));
    QVERIFY_EXCEPTION_THROWN(service.subscribe(options, std::make_shared<observation::Wait_channel>()),
        std::invalid_argument);
    QCOMPARE(queries.load(), 0);
    QCOMPARE(supplied->cache_usage().characters, size_t(0));
}

void Filesystem_observation_scheduler_tests::uncapped_workload_preserves_native_delivery_and_detail_bounds_data()
{
    QTest::addColumn<bool>("recursive");
    QTest::newRow("direct") << false;
    QTest::newRow("recursive") << true;
}

void Filesystem_observation_scheduler_tests::uncapped_workload_preserves_native_delivery_and_detail_bounds()
{
    QFETCH(bool, recursive);
    QTemporaryDir workspace;
    QVERIFY(workspace.isValid());
    observation::limits_t limits;
    limits.subscriptions = 1;
    limits.interest_characters = 1;
    limits.native_registrations = 0;
    limits.native_bytes = 0;
    limits.plan_bytes = 0;
    limits.retained_events = 2;
    limits.workload_admission = observation::Workload_admission::UNCAPPED;
    observation::Service service(limits);
    service.use_manual_clock_for_tests();
    observation::Subscription_options options;
    options.mode = recursive ? observation::Watch_mode::RECURSIVE : observation::Watch_mode::DIRECT;
    for (int index = 0; index != 4097; ++index) {
        options.directories.append({workspace.path(), 1});
        options.exact_files.append(workspace.filePath(QStringLiteral("file-%1").arg(index)));
    }
    auto first_channel = std::make_shared<observation::Wait_channel>();
    auto second_channel = std::make_shared<observation::Wait_channel>();
    auto first = service.subscribe(options, first_channel);
    auto first_delivery = first_channel->wait(5s);
    QVERIFY(first_delivery);
    QVERIFY(first.covers_directory(workspace.path()));
    QVERIFY(first.acknowledge(first_delivery->batch.capture));
    first_delivery.reset();

    // Admit the second subscriber after recursive coverage has settled. Joining
    // during expansion can leave its first capture superseded by completed coverage.
    auto second = service.subscribe(options, second_channel);
    auto second_delivery = second_channel->wait(5s);
    QVERIFY(second_delivery);
    QVERIFY(first.covers_directory(workspace.path()));
    QVERIFY(second.covers_directory(workspace.path()));
    const auto resources = service.resource_counts();
    QVERIFY(resources.armed > 0);
    QVERIFY(resources.native_bytes > 0);
    // Recursive expansion owns plan storage on both platforms; Linux direct
    // watches need only native registrations. Uncapped admission must permit both.
    if (recursive) {
        QVERIFY(resources.plan_bytes > 0);
    }
    QVERIFY(second.acknowledge(second_delivery->batch.capture));
    second_delivery.reset();
    observation::Native_batch edits;
    edits.root = edits.scope = workspace.path();
    for (int index = 0; index != 8; ++index) {
        edits.events.append({workspace.filePath(QStringLiteral("file-%1").arg(index)), {},
            observation::Event_kind::MODIFIED});
    }
    service.ingest_for_tests(first, edits);
    service.advance_clock_for_tests(4s);
    auto promoted = first_channel->wait(5s);
    QVERIFY(promoted);
    QVERIFY(promoted->batch.rescan_required);
    QVERIFY(promoted->batch.events.size() <= 2);
    first.reset();
    second.reset();
    promoted.reset();
    QTRY_COMPARE_WITH_TIMEOUT(service.resource_counts().plan_bytes, size_t(0), 5000);
}

QTEST_GUILESS_MAIN(Filesystem_observation_scheduler_tests)
#include "filesystem_observation_scheduler_tests.moc"
