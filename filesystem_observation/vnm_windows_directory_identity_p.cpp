#include "vnm_windows_directory_identity_p.h"
#include "vnm_native_test_hooks_p.h"
#include "vnm_path_name.h"

#include <QDir>
#include <QScopeGuard>

#include <cstring>
#include <string>

namespace vnm::filesystem_observation::detail {
namespace {

bool valid_directory(HANDLE directory)
{
    FILE_STANDARD_INFO standard{};
    if (!GetFileInformationByHandleEx(directory, FileStandardInfo, &standard, sizeof(standard))) {
        return false;
    }
    if (!standard.Directory || standard.DeletePending) {
        SetLastError(ERROR_FILE_INVALID);
        return false;
    }
    return true;
}

bool extended_identity(HANDLE directory, windows_directory_identity_t& identity)
{
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    const DWORD error = native_test_hooks::windows_file_id_error.load();
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
#endif
    FILE_ID_INFO information{};
    if (!GetFileInformationByHandleEx(directory, FileIdInfo, &information, sizeof(information))) {
        return false;
    }
    identity = {};
    identity.extended = true;
    identity.volume_serial = information.VolumeSerialNumber;
    std::memcpy(identity.file_id.data(), &information.FileId, identity.file_id.size());
    return true;
}

bool fallback_identity(HANDLE directory, windows_directory_identity_t& identity)
{
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(directory, &information)) {
        return false;
    }
    identity = {};
    identity.volume_serial = information.dwVolumeSerialNumber;
    std::memcpy(identity.file_id.data(), &information.nFileIndexHigh, sizeof(DWORD));
    std::memcpy(identity.file_id.data() + sizeof(DWORD), &information.nFileIndexLow, sizeof(DWORD));
    return true;
}

bool unsupported_identity(DWORD error)
{
    return error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_PARAMETER;
}

QString identity_error(const char* operation, DWORD error)
{
    return QStringLiteral("%1 failed (Windows error %2)")
        .arg(QString::fromLatin1(operation)).arg(error);
}

} // namespace

bool same_windows_directory_identity(const windows_directory_identity_t& left,
    const windows_directory_identity_t& right)
{
    return left.extended == right.extended && left.volume_serial == right.volume_serial &&
        left.file_id == right.file_id;
}

bool windows_directory_handles_match(HANDLE held, HANDLE current)
{
    if (!valid_directory(held) || !valid_directory(current)) {
        return false;
    }
    windows_directory_identity_t held_identity;
    windows_directory_identity_t current_identity;
    if (extended_identity(held, held_identity) && extended_identity(current, current_identity)) {
        return same_windows_directory_identity(held_identity, current_identity);
    }
    const DWORD error = GetLastError();
    if (!unsupported_identity(error)) {
        SetLastError(error);
        return false;
    }
    return fallback_identity(held, held_identity) && fallback_identity(current, current_identity) &&
        same_windows_directory_identity(held_identity, current_identity);
}

bool capture_windows_directory_identity(const QString& directory,
    windows_directory_identity_t& identity, QString& final_path, QString& error, bool* missing)
{
    error.clear();
    if (missing) {
        *missing = false;
    }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    const DWORD open_error = native_test_hooks::windows_open_error.load();
    if (open_error != ERROR_SUCCESS) {
        if (missing) {
            *missing = open_error == ERROR_FILE_NOT_FOUND || open_error == ERROR_PATH_NOT_FOUND;
        }
        error = identity_error("CreateFileW", open_error);
        return false;
    }
#endif
    const std::wstring path = QDir::toNativeSeparators(directory).toStdWString();
    const HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD open_failure = GetLastError();
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::windows_failed_identity_opens;
#endif
        if (missing) {
            *missing = open_failure == ERROR_FILE_NOT_FOUND || open_failure == ERROR_PATH_NOT_FOUND;
        }
        error = identity_error("CreateFileW", open_failure);
        return false;
    }
    const auto close = qScopeGuard([&] { CloseHandle(handle); });
    windows_directory_identity_t captured;
    if (!valid_directory(handle)) {
        error = identity_error("Directory identity", GetLastError());
        return false;
    }
    if (!extended_identity(handle, captured)) {
        const DWORD identity_failure = GetLastError();
        if (!unsupported_identity(identity_failure)) {
            error = identity_error("Directory identity", identity_failure);
            return false;
        }
        if (!fallback_identity(handle, captured)) {
            error = identity_error("Directory identity", GetLastError());
            return false;
        }
    }
    std::array<wchar_t, 32768> resolved{};
    const DWORD length = GetFinalPathNameByHandleW(handle, resolved.data(),
        static_cast<DWORD>(resolved.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= resolved.size()) {
        error = identity_error("GetFinalPathNameByHandleW",
            length == 0 ? GetLastError() : ERROR_FILENAME_EXCED_RANGE);
        return false;
    }
    QString target = QString::fromWCharArray(resolved.data(), static_cast<int>(length));
    if (target.startsWith(QStringLiteral("\\\\?\\UNC\\"), Qt::CaseInsensitive)) {
        target = QStringLiteral("\\\\") + target.mid(8);
    }
    else
    if (target.startsWith(QStringLiteral("\\\\?\\"))) {
        target.remove(0, 4);
    }
    identity = captured;
    final_path = path_name::normalized(target);
    return true;
}

} // namespace vnm::filesystem_observation::detail
