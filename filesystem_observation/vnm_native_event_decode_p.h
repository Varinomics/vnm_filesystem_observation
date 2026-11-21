#pragma once

#include "vnm_filesystem_native_event.h"

#include <cstdint>

namespace vnm::filesystem_observation::detail {

void mark_native_rescan(Native_batch& batch, const QString& diagnostic,
    Native_reason reason = Native_reason::DETAIL_UNAVAILABLE);
bool append_native_event(Native_batch& batch, Event event);
Native_batch complete_native_batch(Native_batch batch, const QString& root, quint64 revision);
#if defined(Q_OS_WIN) || defined(Q_OS_MACOS)
struct Native_decode_result
{
    Native_batch batch;
    bool budget_exceeded = false;
};
#endif

#ifdef Q_OS_WIN
Native_decode_result decode_windows_notifications(const QString& root, const char* bytes, uint32_t byte_count);
Native_decode_result decode_windows_extended_notifications(const QString& root, const char* bytes, uint32_t byte_count);
#endif
#ifdef Q_OS_MACOS
Native_decode_result decode_macos_notifications(
    const QString& root, const QString& native_root,
    size_t count, const char* const* paths, const uint32_t* flags,
    const uint64_t* ids, uint64_t baseline);
#endif

} // namespace vnm::filesystem_observation::detail
