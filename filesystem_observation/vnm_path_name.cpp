#include "vnm_path_name.h"
#include "vnm_filesystem_observation_variant.h"

#include <QDir>
#include <QFile>
#include <QSet>

#if defined(Q_OS_WIN)
#  if !defined(NOMINMAX)
#    define NOMINMAX
#  endif
#  include <windows.h>
#elif defined(Q_OS_MACOS)
#  include <unistd.h>
#endif

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

VNM_FILESYSTEM_OBSERVATION_REFERENCE_VARIANT(path_name)

namespace vnm::path_name {

namespace {

int compare_spelling(
    QStringView left,
    QStringView right,
    Comparison_mode mode)
{
#if defined(Q_OS_WIN)
    Q_ASSERT(left.size() <= std::numeric_limits<int>::max());
    Q_ASSERT(right.size() <= std::numeric_limits<int>::max());
    const int result = CompareStringOrdinal(
        reinterpret_cast<LPCWCH>(left.utf16()),
        static_cast<int>(left.size()),
        reinterpret_cast<LPCWCH>(right.utf16()),
        static_cast<int>(right.size()),
        mode == Comparison_mode::ORDINAL_IGNORE_CASE);
    Q_ASSERT(result != 0);
    if (result == CSTR_LESS_THAN) {
        return -1;
    }
    if (result == CSTR_GREATER_THAN) {
        return 1;
    }
    if (result == CSTR_EQUAL) {
        return 0;
    }
#endif
    return left.compare(
        right,
        mode == Comparison_mode::ORDINAL_IGNORE_CASE
            ? Qt::CaseInsensitive
            : Qt::CaseSensitive);
}

int compare_component(
    const Key_component& left,
    const Key_component& right)
{
    if (left.mode != right.mode) {
        return left.mode < right.mode ? -1 : 1;
    }
    return compare_spelling(left.spelling, right.spelling, left.mode);
}

int compare_key(const Key& left, const Key& right)
{
    const int root_order = compare_component(left.root, right.root);
    if (root_order != 0) {
        return root_order;
    }

    const qsizetype common_count = std::min(
        left.components.size(),
        right.components.size());
    for (qsizetype index = 0; index < common_count; ++index) {
        const int component_order = compare_component(
            left.components.at(index),
            right.components.at(index));
        if (component_order != 0) {
            return component_order;
        }
    }
    if (left.components.size() == right.components.size()) {
        return 0;
    }
    return left.components.size() < right.components.size() ? -1 : 1;
}

#if defined(Q_OS_WIN)
class Windows_handle final
{
public:
    explicit Windows_handle(HANDLE handle)
    :
        m_handle(handle)
    {}

    ~Windows_handle()
    {
        if (m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
    }

    Windows_handle(const Windows_handle&) = delete;
    Windows_handle& operator=(const Windows_handle&) = delete;

    HANDLE get() const { return m_handle; }

private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;
};

Directory_case_sensitivity query_windows_case_sensitivity(
    const QString& directory_path)
{
    if (directory_path.isEmpty()) {
        return Directory_case_sensitivity::UNKNOWN;
    }
    const QString native_path = QDir::toNativeSeparators(directory_path);
    const Windows_handle directory(CreateFileW(
        reinterpret_cast<LPCWSTR>(native_path.utf16()),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));
    if (directory.get() == INVALID_HANDLE_VALUE) {
        return Directory_case_sensitivity::UNKNOWN;
    }

    FILE_CASE_SENSITIVE_INFO information{};
    if (!GetFileInformationByHandleEx(
            directory.get(),
            FileCaseSensitiveInfo,
            &information,
            sizeof(information)))
    {
        return Directory_case_sensitivity::UNKNOWN;
    }
    return (information.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0
        ? Directory_case_sensitivity::SENSITIVE
        : Directory_case_sensitivity::INSENSITIVE;
}
#elif defined(Q_OS_MACOS)
Directory_case_sensitivity query_platform_case_sensitivity(const QString& directory_path)
{
    const QByteArray native_path = QFile::encodeName(directory_path);
    const long sensitivity = ::pathconf(native_path.constData(), _PC_CASE_SENSITIVE);
    if (sensitivity < 0) {
        return Directory_case_sensitivity::UNKNOWN;
    }
    return sensitivity == 0
        ? Directory_case_sensitivity::INSENSITIVE
        : Directory_case_sensitivity::SENSITIVE;
}
#else
Directory_case_sensitivity query_platform_case_sensitivity(const QString&)
{
    return Directory_case_sensitivity::SENSITIVE;
}
#endif

Comparison_mode comparison_mode(Directory_case_sensitivity sensitivity)
{
    return sensitivity == Directory_case_sensitivity::INSENSITIVE
        ? Comparison_mode::ORDINAL_IGNORE_CASE
        : Comparison_mode::ORDINAL;
}

struct Split_path
{
    Key_component root;
    QString query_parent;
    QStringList components;
};

Split_path split_path(const QString& normalized_path)
{
    Split_path result;
    QString remainder = normalized_path;

#if defined(Q_OS_WIN)
    if (remainder.size() >= 3 &&
        remainder.at(1) == QLatin1Char(':') &&
        remainder.at(2) == QLatin1Char('/'))
    {
        result.root = {
            Comparison_mode::ORDINAL_IGNORE_CASE,
            remainder.left(3),
        };
        result.query_parent = result.root.spelling;
        remainder.remove(0, 3);
    }
    else
    if (remainder.startsWith(QStringLiteral("//"))) {
        const qsizetype server_end = remainder.indexOf(QLatin1Char('/'), 2);
        const qsizetype share_end = server_end < 0
            ? -1
            : remainder.indexOf(QLatin1Char('/'), server_end + 1);
        const qsizetype root_end = share_end < 0
            ? remainder.size()
            : share_end;
        if (server_end < 0 || server_end + 1 >= root_end) {
            result.root = {Comparison_mode::ORDINAL, normalized_path};
            return result;
        }
        result.root = {
            Comparison_mode::ORDINAL_IGNORE_CASE,
            remainder.left(root_end),
        };
        result.query_parent = result.root.spelling;
        remainder.remove(0, root_end);
    }
    else
    if (remainder.size() >= 2 && remainder.at(1) == QLatin1Char(':')) {
        // Drive-relative paths depend on hidden per-drive process state and
        // therefore cannot be compared as stable repository names.
        result.root = {Comparison_mode::ORDINAL, normalized_path};
        return result;
    }
    else {
        result.query_parent = QDir::currentPath();
    }
#else
    if (remainder.startsWith(QLatin1Char('/'))) {
        result.root = {Comparison_mode::ORDINAL, QStringLiteral("/")};
        result.query_parent = result.root.spelling;
        remainder.remove(0, 1);
    }
    else {
        result.query_parent = QDir::currentPath();
    }
#endif

    while (remainder.startsWith(QLatin1Char('/'))) {
        remainder.remove(0, 1);
    }
    result.components = remainder.split(
        QLatin1Char('/'),
        Qt::SkipEmptyParts);
    return result;
}

enum class Key_relation
{
    EXACT,
    WITHIN,
    ANCESTOR,
};

bool matches_captured_key(QStringView path, const Key& interest, Key_relation relation)
{
    if (path.isEmpty()) {
        return false;
    }
    const auto split = split_path(normalized(path.toString()));
    if (!(split.root == interest.root)) {
        return false;
    }
    const auto actual_count = split.components.size();
    const auto interest_count = interest.components.size();
    if ((relation == Key_relation::EXACT && actual_count != interest_count) ||
        (relation == Key_relation::WITHIN && actual_count < interest_count) ||
        (relation == Key_relation::ANCESTOR && actual_count > interest_count))
    {
        return false;
    }
    for (qsizetype index = 0; index < std::min(actual_count, interest_count); ++index) {
        const auto& component = interest.components[index];
        if (compare_spelling(split.components[index], component.spelling, component.mode) != 0) {
            return false;
        }
    }
    return true;
}

std::optional<Key> key_from_cache(
    const QString& path,
    const QMap<QString, Directory_case_sensitivity>& cache)
{
    auto split = split_path(path);
    Key key;
    key.root = split.root;
    for (const auto& component : split.components) {
        const auto found = cache.constFind(split.query_parent);
        if (found == cache.cend()) {
            return std::nullopt;
        }
        key.components.append({comparison_mode(*found), component});
        split.query_parent = normalized(QDir(split.query_parent).filePath(component));
    }
    return key;
}

struct Retained_policy_index
{
    QMap<Key, std::optional<Directory_case_sensitivity>> decisions;
};

Retained_policy_index retained_policy_index(
    const QMap<QString, Directory_case_sensitivity>& cache)
{
    Retained_policy_index result;
    for (auto entry = cache.cbegin(); entry != cache.cend(); ++entry) {
        const auto key = key_from_cache(entry.key(), cache);
        if (!key) {
            continue;
        }
        const auto decision = result.decisions.find(*key);
        if (decision == result.decisions.end()) {
            result.decisions.insert(*key, entry.value());
        }
        else
        if (!decision->has_value() || **decision != entry.value()) {
            *decision = std::nullopt;
        }
    }
    return result;
}

} // namespace

bool operator==(const Key_component& left, const Key_component& right)
{
    return compare_component(left, right) == 0;
}

bool operator<(const Key_component& left, const Key_component& right)
{
    return compare_component(left, right) < 0;
}

bool operator==(const Key& left, const Key& right)
{
    return compare_key(left, right) == 0;
}

bool operator<(const Key& left, const Key& right)
{
    return compare_key(left, right) < 0;
}

QString normalized(const QString& path)
{
    return path.isEmpty()
        ? QString()
        : QDir::cleanPath(QDir::fromNativeSeparators(path));
}

bool matches_key(QStringView path, const Key& interest)
{
    return matches_captured_key(path, interest, Key_relation::EXACT);
}

bool is_within_key(QStringView path, const Key& directory)
{
    return matches_captured_key(path, directory, Key_relation::WITHIN);
}

bool is_ancestor_of_key(QStringView path, const Key& descendant)
{
    return matches_captured_key(path, descendant, Key_relation::ANCESTOR);
}

Key matching_bucket(const Key& captured)
{
    Key bucket = captured;
    for (auto& component : bucket.components) {
        component.mode = Comparison_mode::ORDINAL_IGNORE_CASE;
    }
    return bucket;
}

Key matching_bucket(QStringView path)
{
    const auto split = split_path(normalized(path.toString()));
    Key bucket;
    bucket.root = split.root;
    for (const auto& component : split.components) {
        bucket.components.append({Comparison_mode::ORDINAL_IGNORE_CASE, component});
    }
    return bucket;
}

Policy_epoch::Policy_epoch()
:
#if defined(Q_OS_WIN)
    m_case_sensitivity_query(query_windows_case_sensitivity)
#else
    m_case_sensitivity_query(query_platform_case_sensitivity)
#endif
{}

Policy_epoch::Policy_epoch(Case_sensitivity_query case_sensitivity_query)
:
    m_case_sensitivity_query(std::move(case_sensitivity_query))
{}

Directory_case_sensitivity Policy_epoch::directory_case_sensitivity(
    const QString& exact_parent_spelling) const
{
    const std::scoped_lock lock(m_cache_mutex);
    const auto cached = m_case_sensitivity_by_exact_parent.constFind(
        exact_parent_spelling);
    if (cached != m_case_sensitivity_by_exact_parent.cend()) {
        return cached.value();
    }
    const std::lock_guard query_lock(*m_query_mutex);
    const Directory_case_sensitivity sensitivity =
        m_case_sensitivity_query(exact_parent_spelling);
    m_case_sensitivity_by_exact_parent.insert(
        exact_parent_spelling,
        sensitivity);
    return sensitivity;
}

cache_usage_t Policy_epoch::cache_usage() const
{
    const std::lock_guard lock(m_cache_mutex);
    cache_usage_t usage;
    usage.entries = size_t(m_case_sensitivity_by_exact_parent.size());
    for (auto entry = m_case_sensitivity_by_exact_parent.cbegin();
         entry != m_case_sensitivity_by_exact_parent.cend(); ++entry)
    {
        usage.characters += size_t(entry.key().size());
    }
    return usage;
}

std::shared_ptr<Policy_epoch> Policy_epoch::fork_for_paths(
    const QStringList& paths,
    size_t max_cached_characters,
    const Policy_epoch* retained_epoch,
    bool bounded_workload) const
{
    QStringList parents;
    QSet<QString> seen;
    size_t characters = 0;
    for (const auto& path : paths) {
        auto split = split_path(normalized(path));
        for (const auto& component : split.components) {
            if (!seen.contains(split.query_parent)) {
                const auto count = size_t(split.query_parent.size());
                if (count > std::numeric_limits<size_t>::max() - characters) {
                    throw std::overflow_error("Observation policy parent text accounting overflow");
                }
                if (bounded_workload && (characters > max_cached_characters ||
                    count > max_cached_characters - characters))
                {
                    throw std::invalid_argument("Observation policy parent text budget exhausted");
                }
                characters += count;
                seen.insert(split.query_parent);
                parents.append(split.query_parent);
            }
            split.query_parent = normalized(QDir(split.query_parent).filePath(component));
        }
    }

    auto result = std::make_shared<Policy_epoch>(m_case_sensitivity_query);
    result->m_query_mutex = m_query_mutex;
    std::optional<Retained_policy_index> retained_index;
    for (const auto& parent : parents) {
        std::optional<Directory_case_sensitivity> supplied;
        {
            const std::lock_guard lock(m_cache_mutex);
            const auto found = m_case_sensitivity_by_exact_parent.constFind(parent);
            if (found != m_case_sensitivity_by_exact_parent.cend()) {
                supplied = *found;
            }
        }
        std::optional<Directory_case_sensitivity> retained;
        if (retained_epoch) {
            const std::lock_guard lock(retained_epoch->m_cache_mutex);
            const auto& cache = retained_epoch->m_case_sensitivity_by_exact_parent;
            const auto exact = cache.constFind(parent);
            if (exact != cache.cend()) {
                retained = *exact;
            }
            else
            if (const auto parent_key = key_from_cache(parent, result->m_case_sensitivity_by_exact_parent)) {
                if (!retained_index) {
                    retained_index = retained_policy_index(cache);
                }
                const auto decision = retained_index->decisions.constFind(*parent_key);
                if (decision != retained_index->decisions.cend()) {
                    if (!decision->has_value()) {
                        return {};
                    }
                    retained = **decision;
                }
            }
        }
        if (supplied && retained && *supplied != *retained) {
            return {};
        }
        Directory_case_sensitivity decision;
        if (supplied) {
            decision = *supplied;
        }
        else
        if (retained) {
            decision = *retained;
        }
        else {
            const std::lock_guard query_lock(*m_query_mutex);
            decision = m_case_sensitivity_query(parent);
        }
        result->m_case_sensitivity_by_exact_parent.insert(parent, decision);
    }
    return result;
}

Key Policy_epoch::key(QStringView path) const
{
    const QString normalized_path = normalized(path.toString());
    Split_path split = split_path(normalized_path);
    Key result;
    result.root = std::move(split.root);
    result.components.reserve(split.components.size());
    for (const QString& component : std::as_const(split.components)) {
        result.components.append({
            comparison_mode(directory_case_sensitivity(split.query_parent)),
            component,
        });
        split.query_parent = normalized(
            QDir(split.query_parent).filePath(component));
    }
    return result;
}

bool Policy_epoch::same(QStringView left, QStringView right) const
{
    if (left == right) {
        return true;
    }
    if (left.isEmpty() || right.isEmpty()) {
        return false;
    }
    return key(left) == key(right);
}

bool Policy_epoch::is_within(QStringView path, QStringView directory) const
{
    if (path.isEmpty() || directory.isEmpty()) {
        return false;
    }
    const Key path_key = key(path);
    const Key directory_key = key(directory);
    if (!(path_key.root == directory_key.root) ||
        directory_key.components.size() > path_key.components.size())
    {
        return false;
    }
    for (qsizetype index = 0;
            index < directory_key.components.size();
            ++index)
    {
        if (!(path_key.components.at(index) ==
                directory_key.components.at(index)))
        {
            return false;
        }
    }
    return true;
}

} // namespace vnm::path_name
