#pragma once

#include <QList>
#include <QString>

#include <cstddef>

namespace vnm::filesystem_observation {

enum class Event_kind
{
    CREATED  = 1,
    REMOVED  = 2,
    MODIFIED = 4,
    RENAMED  = 8,
};

// Whether the entry an event names is a directory, as the notification itself
// reports it. inotify and extended Windows notifications carry the entry type.
// Basic Windows notifications carry UNKNOWN; the path's later state is never
// substituted because it may name a different entry. Subscribers treat UNKNOWN
// as possibly a directory.
enum class Entry_type
{
    UNKNOWN,
    DIRECTORY,
    NON_DIRECTORY,
};

struct Event
{
    QString path;
    QString old_path;
    Event_kind kind       = Event_kind::MODIFIED;
    Entry_type entry_type = Entry_type::UNKNOWN;

    bool operator==(const Event&) const = default;
};

enum class Native_reason
{
    CONTENTS_CHANGED,
    DETAIL_UNAVAILABLE,
    QUEUE_OVERFLOW,
    COVERAGE_CHANGED,
    REGISTRATION_FAILED,
    DIRECTORY_FILTER_PENDING,
};

enum class Coverage_state
{
    PENDING,
    COVERED,
    FAILED,
};

// The current requested scope owns this state and any failure diagnostic.
// Observed coverage does not discharge a consumer's retained readback capture.
struct Coverage_status
{
    Coverage_state state = Coverage_state::PENDING;
    QString diagnostic;
};

struct Native_batch
{
    QString root;
    QString scope;
    QList<Event> events;
    quint64 coverage_revision = 0;
    bool rescan_required = false;
    QString diagnostic;
    Native_reason reason = Native_reason::CONTENTS_CHANGED;
    // A partial rename can require reconciliation without losing observation:
    // its retained endpoints completely bound the affected logical interests.
    // Any lost, malformed or budget-discarded detail keeps this false.
    bool rescan_event_paths_complete = false;
    // Only an owner-requested filter replan with continuous physical coverage
    // can reconcile the consumer without invalidating its policy-source reads.
    // Logical eligibility may remain pending; this does not certify coverage.
    bool consumer_reconciliation_only = false;
    // A newly admitted scope needs its own post-arm readback. This says nothing
    // about a change to other consumers; source work and lost coverage stay false.
    // The cause survives pending eligibility and its later post-arm readback.
    bool initial_admission_only = false;
};

struct Resource_counts
{
    // Native registrations count physical anchors on Windows and nonrecursive
    // registrations on Linux. Logical coverage is independently accounted below.
    int desired = 0;
    int armed = 0;
    int failed = 0;
    int native_threads = 0;
    int scan_pending = 0;
    int scan_failed = 0;
    int retiring = 0;
    int logical_directories = 0;
    int covered_logical_directories = 0;
    size_t native_bytes = 0;
    size_t plan_bytes = 0;
    size_t scan_result_bytes = 0;
    size_t scan_jobs = 0;
    size_t scan_threads = 0;
    size_t handoff_detail_bytes = 0;
    size_t peak_handoff_detail_bytes = 0;
    quint64 native_batches = 0;
    // Physical overflow indications, before registration/subscriber fanout.
    quint64 kernel_overflows = 0;
    // Native reads/completions with any decoder-budget truncation, once per read.
    quint64 decoder_budget_losses = 0;
    // Pending registration handoffs that discarded detail, once until consumed.
    quint64 handoff_overflows = 0;
};

} // namespace vnm::filesystem_observation
