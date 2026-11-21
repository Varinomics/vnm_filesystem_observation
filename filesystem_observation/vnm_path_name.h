#pragma once

#include <QList>
#include <QMap>
#include <QString>
#include <QStringView>
#include <QStringList>

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>

namespace vnm::path_name {

enum class Directory_case_sensitivity
{
    SENSITIVE,
    INSENSITIVE,
    UNKNOWN,
};

enum class Comparison_mode
{
    ORDINAL,
    ORDINAL_IGNORE_CASE,
};

struct Key_component
{
    Comparison_mode mode = Comparison_mode::ORDINAL;
    QString spelling;
};

struct Key
{
    Key_component root;
    QList<Key_component> components;
};

bool operator==(const Key_component& left, const Key_component& right);
bool operator<(const Key_component& left, const Key_component& right);
bool operator==(const Key& left, const Key& right);
bool operator<(const Key& left, const Key& right);

QString normalized(const QString& path);

// Compare using the interest's captured modes. Event descendants never add
// historical parent spellings to a policy epoch.
bool matches_key(QStringView path, const Key& interest);
bool is_within_key(QStringView path, const Key& directory);
bool is_ancestor_of_key(QStringView path, const Key& descendant);

// A coarse index for captured-key matching, with no policy acquisition. Equal
// buckets still require matches_key against each candidate's captured modes.
Key matching_bucket(const Key& captured);
Key matching_bucket(QStringView path);

struct cache_usage_t
{
    size_t entries = 0;
    size_t characters = 0;
};

class Policy_epoch final
{
public:
    using Case_sensitivity_query =
        std::function<Directory_case_sensitivity(const QString&)>;

    Policy_epoch();
    explicit Policy_epoch(Case_sensitivity_query case_sensitivity_query);

    Key key(QStringView path) const;
    bool same(QStringView left, QStringView right) const;
    bool is_within(QStringView path, QStringView directory) const;

    // Independent snapshot of named interest-parent decisions. Existing source
    // decisions win; a conflicting retained decision returns null. Neither source
    // nor retained epoch gains entries. With bounded_workload, the text bound
    // includes every prefix; otherwise allocation availability governs growth.
    std::shared_ptr<Policy_epoch> fork_for_paths(
        const QStringList& paths,
        size_t max_cached_characters,
        const Policy_epoch* retained_epoch = nullptr,
        bool bounded_workload = true) const;
    cache_usage_t cache_usage() const;

private:
    Directory_case_sensitivity directory_case_sensitivity(
        const QString& exact_parent_spelling) const;

    Case_sensitivity_query m_case_sensitivity_query;
    std::shared_ptr<std::mutex> m_query_mutex = std::make_shared<std::mutex>();
    mutable std::mutex m_cache_mutex;
    mutable QMap<QString, Directory_case_sensitivity>
        m_case_sensitivity_by_exact_parent;
};

} // namespace vnm::path_name
