#pragma once

#include <QString>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstdint>

namespace vnm::filesystem_observation::detail {

struct windows_directory_identity_t
{
    uint64_t volume_serial = 0;
    std::array<unsigned char, 16> file_id{};
    bool extended = false;
};

bool same_windows_directory_identity(const windows_directory_identity_t& left,
    const windows_directory_identity_t& right);

// Captures values only; the delete-sharing attributes handle closes before
// return. Identity and normalized resolved path are assigned only on success.
// Missing distinguishes a nonexistent path from access or identity failures.
bool capture_windows_directory_identity(const QString& directory,
    windows_directory_identity_t& identity, QString& final_path, QString& error,
    bool* missing = nullptr);

// Keeps both handles on the same identity method when extended IDs are absent.
// Failure preserves the Windows error for the native owner's diagnostic.
bool windows_directory_handles_match(HANDLE held, HANDLE current);

} // namespace vnm::filesystem_observation::detail
