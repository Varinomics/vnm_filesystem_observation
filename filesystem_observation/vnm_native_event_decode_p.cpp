#include "vnm_native_event_decode_p.h"
#include "vnm_path_name.h"

#include <QDir>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <cstddef>
#include <cstring>
#include <utility>

namespace vnm::filesystem_observation::detail {

void mark_native_rescan(Native_batch& batch, const QString& diagnostic,
    Native_reason reason)
{
    batch.rescan_required = true;
    batch.rescan_event_paths_complete = false;
    batch.consumer_reconciliation_only = false;
    if (batch.reason == Native_reason::CONTENTS_CHANGED || reason == Native_reason::QUEUE_OVERFLOW) {
        batch.reason = reason;
    }
    // Keep the first cause; diagnostic accumulation must itself stay bounded.
    if (batch.diagnostic.isEmpty()) {
        batch.diagnostic = diagnostic.left(512);
    }
}

bool append_native_event(Native_batch& batch, Event event)
{
    constexpr qsizetype maximum_events = 256;
    constexpr qsizetype maximum_path_characters = 32768;
    qsizetype characters = event.path.size() + event.old_path.size();
    for (const Event& retained : batch.events) {
        characters += retained.path.size() + retained.old_path.size();
    }
    if (batch.events.size() >= maximum_events ||
        characters > maximum_path_characters)
    {
        mark_native_rescan(batch, QStringLiteral("Native event detail budget exceeded"));
        return false;
    }
    batch.events.append(std::move(event));
    return true;
}

Native_batch complete_native_batch(Native_batch batch, const QString& root, quint64 revision)
{
    batch.root = root;
    batch.scope = root;
    batch.coverage_revision = revision;
    if (batch.events.isEmpty()) {
        mark_native_rescan(batch, QStringLiteral("Native completion has no path detail"));
    }
    for (const Event& event : batch.events) {
        if (event.kind == Event_kind::RENAMED &&
            (event.path.isEmpty() || event.old_path.isEmpty()))
        {
            const bool paths_complete = (!batch.rescan_required || batch.rescan_event_paths_complete) &&
                (!event.path.isEmpty() || !event.old_path.isEmpty());
            mark_native_rescan(batch, QStringLiteral("Rename endpoint association is incomplete"));
            batch.rescan_event_paths_complete = paths_complete;
        }
    }
    return batch;
}

#ifdef Q_OS_WIN
namespace {

Entry_type record_entry_type(const FILE_NOTIFY_INFORMATION&) { return Entry_type::UNKNOWN; }

Entry_type record_entry_type(const FILE_NOTIFY_EXTENDED_INFORMATION& record)
{
    return (record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        ? Entry_type::DIRECTORY : Entry_type::NON_DIRECTORY;
}

template<class Record>
Native_decode_result decode_windows_records(const QString& root, const char* bytes, uint32_t byte_count)
{
    Native_decode_result result;
    auto& batch = result.batch;
    const auto append = [&](Event event) {
        result.budget_exceeded |= !append_native_event(batch, std::move(event));
    };
    constexpr DWORD header_size = offsetof(Record, FileName);
    DWORD offset = 0;
    QString old_path;
    Entry_type old_type = Entry_type::UNKNOWN;
    while (offset < byte_count) {
        if (byte_count - offset < header_size) {
            mark_native_rescan(batch, QStringLiteral("Truncated Windows notification header"));
            break;
        }
        // Windows guarantees DWORD alignment, including for extended records
        // whose LARGE_INTEGER fields give the C++ structure stricter alignment.
        Record header{};
        std::memcpy(&header, bytes + offset, header_size);
        const auto* record = &header;
        if (record->FileNameLength == 0 || record->FileNameLength % sizeof(wchar_t) != 0 ||
            record->FileNameLength > byte_count - offset - header_size)
        {
            mark_native_rescan(batch, QStringLiteral("Malformed Windows notification path"));
            break;
        }
        const QString relative = QString::fromWCharArray(
            reinterpret_cast<const wchar_t*>(bytes + offset + header_size),
            static_cast<int>(record->FileNameLength / sizeof(wchar_t)));
        const QString path = vnm::path_name::normalized(QDir(root).filePath(relative));
        const Entry_type entry_type = record_entry_type(header);
        if (!old_path.isEmpty() &&
            (record->Action != FILE_ACTION_RENAMED_NEW_NAME || old_type != entry_type))
        {
            append({{}, std::move(old_path), Event_kind::RENAMED, old_type});
            old_path.clear();
        }
        switch (record->Action) {
            case FILE_ACTION_ADDED:
                append({path, {}, Event_kind::CREATED, entry_type});
                break;
            case FILE_ACTION_REMOVED:
                append({path, {}, Event_kind::REMOVED, entry_type});
                break;
            case FILE_ACTION_MODIFIED:
                append({path, {}, Event_kind::MODIFIED, entry_type});
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
                old_path = path;
                old_type = entry_type;
                break;
            case FILE_ACTION_RENAMED_NEW_NAME:
                append({path, std::move(old_path), Event_kind::RENAMED, entry_type});
                old_path.clear();
                break;
            default:
                mark_native_rescan(batch, QStringLiteral("Unknown Windows notification action"));
                break;
        }
        if (record->NextEntryOffset == 0) {
            break;
        }
        if (record->NextEntryOffset < header_size + record->FileNameLength ||
            record->NextEntryOffset % sizeof(DWORD) != 0 ||
            record->NextEntryOffset >= byte_count - offset)
        {
            mark_native_rescan(batch, QStringLiteral("Malformed Windows notification offset"));
            break;
        }
        offset += record->NextEntryOffset;
    }
    if (!old_path.isEmpty()) {
        append({{}, std::move(old_path), Event_kind::RENAMED, old_type});
    }
    batch = complete_native_batch(std::move(batch), root, 0);
    return result;
}

} // namespace

Native_decode_result decode_windows_notifications(const QString& root, const char* bytes, uint32_t byte_count)
{
    return decode_windows_records<FILE_NOTIFY_INFORMATION>(root, bytes, byte_count);
}

Native_decode_result decode_windows_extended_notifications(const QString& root, const char* bytes, uint32_t byte_count)
{
    return decode_windows_records<FILE_NOTIFY_EXTENDED_INFORMATION>(root, bytes, byte_count);
}
#endif

} // namespace vnm::filesystem_observation::detail
