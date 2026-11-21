#include "vnm_direct_registry_p.h"
#include "vnm_direct_native_backend_p.h"
#include "vnm_direct_native_drain_p.h"
#include "vnm_directory_scan_p.h"
#include "vnm_native_test_hooks_p.h"
#ifdef Q_OS_WIN
#include "vnm_windows_directory_identity_p.h"
#endif

#include <QDir>
#include <QFileInfo>
#include <QMap>
#include <QScopeGuard>


#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <set>
#include <thread>
#include <utility>
#include <vector>

namespace vnm::filesystem_observation::detail {
namespace {

using Clock = std::chrono::steady_clock;
constexpr auto k_retry_interval = std::chrono::seconds(1);
std::atomic_uint64_t s_next_coverage_revision = 1;
constexpr int k_root_scan_concurrency = 4;
constexpr int k_native_operations_per_turn = 16;

enum class Reconciliation_cause
{
    INITIAL_ADMISSION,
    CONSUMER_RECONCILIATION,
    SOURCE_RECONCILIATION,
};

QString recovery_parent(const QString& path)
{
    auto parent = QFileInfo(path).absolutePath();
    while (true) {
#if defined(VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS) && defined(Q_OS_WIN)
        ++native_test_hooks::windows_parent_metadata_probes;
#endif
        if (QFileInfo(parent).isDir()) {
            break;
        }
        const auto next = QFileInfo(parent).absolutePath();
        if (next == parent) {
            break;
        }
        parent = next;
    }
    return path_name::normalized(parent);
}

bool add_usage(size_t& used, size_t count)
{
    if (count > std::numeric_limits<size_t>::max() - used) {
        return false;
    }
    used += count;
    return true;
}

} // namespace

struct Direct_registry::Impl
{
    struct Plan_charge;
    struct Root;
    struct Interest;
    struct Entry
    {
        QString path;
        path_name::Key key;
        uint64_t native_id = 0;
        uint64_t revision = 0;
        QString failure;
        Coverage_state state = Coverage_state::PENDING;
        Clock::time_point retry_at{};
        Clock::time_point validate_at{};
        Clock::time_point native_due = Clock::time_point::max();
        Interest* interests = nullptr;
#ifdef Q_OS_WIN
        // Logical directories retain identity values, never directory handles.
        // Only the shared ancestor entry owns a Windows native registration.
        std::shared_ptr<Entry> anchor;
        std::shared_ptr<Plan_charge> identity_charge;
        windows_directory_identity_t identity{};
        QString physical_path;
        path_name::Key physical_key;
        uint64_t anchor_revision = 0;
        bool identity_known = false;
        bool physical = false;
        bool desired = false;
        bool anchor_input = false;
        size_t boundary_reasons = 0;
        bool budget_refused = false;
#endif
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        bool unavailable = false;
#endif
    };

    // Graph objects own these links; the reverse index owns no graph objects
    // and allocates no additional map nodes. Node admission charges their size.
    struct Interest
    {
        Entry* entry = nullptr;
        std::weak_ptr<Root> root;
        Interest* next = nullptr;
        Interest** previous = nullptr;

        ~Interest() { clear(); }
        void clear()
        {
            if (previous) {
                *previous = next;
                if (next) {
                    next->previous = previous;
                }
            }
            entry = nullptr;
            previous = nullptr;
            next = nullptr;
            root.reset();
        }
        void set(const std::shared_ptr<Entry>& value, const std::shared_ptr<Root>& owner)
        {
            clear();
            entry = value.get();
            root = owner;
            next = entry->interests;
            previous = &entry->interests;
            if (next) {
                next->previous = &this->next;
            }
            entry->interests = this;
        }
    };

    struct Plan_budget
    {
        std::atomic_size_t used = 0;
        size_t limit = 0;
    };

#ifdef Q_OS_WIN
    struct Route_node
    {
        std::map<path_name::Key_component, Route_node> children;
        std::map<Entry*, std::weak_ptr<Entry>> entries;
    };

    static const path_name::Key_component& route_component(const path_name::Key& key, qsizetype index)
    {
        return index == 0 ? key.root : key.components[index - 1];
    }

    void insert_windows_route(const path_name::Key& key, const std::shared_ptr<Entry>& entry)
    {
        auto* node = &m_windows_routes;
        for (qsizetype index = 0; index <= key.components.size(); ++index) {
            node = &node->children[route_component(key, index)];
        }
        node->entries.emplace(entry.get(), entry);
    }

    static bool erase_windows_route(Route_node& node, const path_name::Key& key, Entry* entry,
        qsizetype index = 0)
    {
        if (index > key.components.size()) {
            node.entries.erase(entry);
        }
        else {
            const auto child = node.children.find(route_component(key, index));
            if (child != node.children.end() && erase_windows_route(child->second, key, entry, index + 1)) {
                node.children.erase(child);
            }
        }
        return node.entries.empty() && node.children.empty();
    }

    template<class Visitor>
    static void visit_windows_routes(const Route_node& node, bool descendants, const Visitor& visit)
    {
        for (const auto& [pointer, weak] : node.entries) {
            Q_UNUSED(pointer);
            if (const auto entry = weak.lock()) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
                ++native_test_hooks::windows_route_entry_visits;
#endif
                visit(entry);
            }
        }
        if (descendants) {
            for (const auto& [component, child] : node.children) {
                Q_UNUSED(component);
                visit_windows_routes(child, true, visit);
            }
        }
    }

    template<class Visitor>
    static void find_windows_routes(const Route_node& node, const path_name::Key& key,
        qsizetype index, bool descendants, const Visitor& visit)
    {
        if (index > key.components.size()) {
            visit_windows_routes(node, descendants, visit);
            return;
        }
        auto component = route_component(key, index);
        const auto find = [&] {
            const auto child = node.children.find(component);
            if (child != node.children.end()) {
                find_windows_routes(child->second, key, index + 1, descendants, visit);
            }
        };
        find();
        if (index != 0) {
            component.mode = path_name::Comparison_mode::ORDINAL_IGNORE_CASE;
            find();
        }
    }

    template<class Visitor>
    void find_windows_routes(const QString& path, bool descendants, const Visitor& visit) const
    {
        if (path.isEmpty()) {
            return;
        }
        // Split event spelling without filesystem queries or a retained policy.
        // The live interest trie supplies every comparison mode used for lookup.
        const auto key = path_name::Policy_epoch([](const QString&) {
            return path_name::Directory_case_sensitivity::UNKNOWN;
        }).key(path);
        find_windows_routes(m_windows_routes, key, 0, descendants, visit);
    }

    struct Anchor_candidate
    {
        QString path;
        std::shared_ptr<Plan_charge> retention;
    };
#endif

    struct Plan_charge
    {
        std::shared_ptr<Plan_budget> budget;
        size_t bytes = 0;
        ~Plan_charge() { budget->used.fetch_sub(bytes); }
    };

    struct Client;

    struct Coverage_read
    {
        path_name::Key key;
        Coverage_status status;
        uint64_t revision = 0;
    };

    struct Read_view
    {
        QList<Coverage_read> roots;
        QMap<path_name::Key, QList<qsizetype>> root_indices;
        QList<path_name::Key> interests;
        bool requested = false;

        const Coverage_read* find_root(const QString& path) const
        {
            const auto candidates = root_indices.constFind(path_name::matching_bucket(path));
            if (candidates == root_indices.cend()) {
                return nullptr;
            }
            // Preserve the first captured match, including case-distinct roots
            // and duplicate registrations. Exact spelling has no precedence.
            for (const auto index : *candidates) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
                ++native_test_hooks::coverage_read_candidates;
#endif
                const auto& root = roots[index];
                if (path_name::matches_key(path, root.key)) {
                    return &root;
                }
            }
            return nullptr;
        }
    };

    struct Root
    {
        uint64_t id = 0;
        QString path;
        path_name::Key key;
        std::weak_ptr<Client> owner;
        std::shared_ptr<path_name::Policy_epoch> policy;
        std::shared_ptr<Entry> content;
        std::shared_ptr<Entry> guard;
        Interest content_interest;
        Interest guard_interest;
        uint64_t content_revision = 0;
        uint64_t guard_revision = 0;
        uint64_t revision = 0;
        bool covered = false;
        Coverage_status read_status;
        uint64_t read_revision = 0;
        uint64_t published_native_revision = 0;
        QString published_failure;
        bool refresh = true;
        Clock::time_point parent_retry_at{};
        Clock::time_point scan_retry_at = Clock::time_point::max();
        bool resources_dirty = true;
        int scan_pending = 0;
        int scan_failed = 0;
        bool node_budget_refused = false;
        Watch_mode mode = Watch_mode::DIRECT;
        int maximum_depth = 0;
        Native_watcher::Directory_filter filter;
        uint64_t eligibility_generation = 0;
        // Source work is absorbing until this plan is replaced after coverage.
        Reconciliation_cause cause = Reconciliation_cause::INITIAL_ADMISSION;
        QString expansion_failure;
        bool budget_refused = false;
        Clock::time_point expansion_retry_at{};
        struct Node
        {
            std::shared_ptr<Plan_charge> charge;
            std::shared_ptr<Entry> entry;
            Interest interest;
            std::shared_ptr<path_name::Policy_epoch> policy;
            int depth = 0;
            uint64_t scan = 0;
            uint64_t observed_revision = 0;
            std::shared_ptr<std::atomic_bool> active;
            std::set<path_name::Key> children;
            std::set<path_name::Key> seen;
            QString error;
            Clock::time_point retry_at{};
            bool complete = false;
            bool rescan_covered = false;
            bool budget_refused = false;
            bool again = false;
            bool filter_pending = false;
            ~Node()
            {
                if (active) {
                    active->store(false);
                }
            }
        };
        QMap<path_name::Key, std::shared_ptr<Node>> nodes;
        bool expansion_complete = true;
        bool initial_attempted = false;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        bool forced_failure = false;
#endif
    };

    struct Client
    {
        uint64_t id = 0;
        Callback callback;
        QList<Watch_spec> paths;
        QList<path_name::Key> interest_keys;
        Watch_mode mode = Watch_mode::DIRECT;
        Native_watcher::Directory_filter filter;
        uint64_t eligibility_generation = 0;
        std::shared_ptr<path_name::Policy_epoch> policy;
        QList<std::shared_ptr<Root>> roots;
        QMap<path_name::Key, QList<qsizetype>> root_indices;
        QList<std::shared_ptr<Root>> retiring_roots;
        uint64_t requested = 0;
        uint64_t applied = 0;
        uint64_t prepared = 0;
        uint64_t delivered = 0;
        size_t callbacks = 0;
        bool active = true;
        bool initial = false;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        bool invalidate_content = false;
        bool inject_overflow = false;
        int expansions = 0;
        Maintenance_counts maintenance;
        std::function<void(Native_watcher::Expansion_stage)> expansion_observer;
#endif
    };

    bool live(const std::shared_ptr<Root>& root) const
    {
        const auto owner = root ? root->owner.lock() : nullptr;
        return owner && owner->active && owner->roots.contains(root);
    }

    QMap<uint64_t, std::shared_ptr<Root>> interested_roots(const Entry& entry) const
    {
        QMap<uint64_t, std::shared_ptr<Root>> result;
        for (auto* interest = entry.interests; interest; interest = interest->next) {
            const auto root = interest->root.lock();
            if (live(root)) {
                result.insert(root->id, root);
            }
            else
            if (const auto owner = root ? root->owner.lock() : nullptr;
                owner && owner->active && owner->retiring_roots.contains(root))
            {
                // A retiring filter plan protects its replacement before that
                // plan has rediscovered the retained descendant links.
                for (const auto& current : owner->roots) {
                    if (path_name::is_within_key(entry.path, current->key)) {
                        result.insert(current->id, current);
                    }
                }
            }
        }
        return result;
    }

    void mark_root(const std::shared_ptr<Root>& root)
    {
        root->refresh = true;
        root->resources_dirty = true;
        m_dirty_roots.insert(root->id, root);
        m_reconcile_roots.insert(root->id, root);
    }

    void mark_entry(const Entry& entry, bool failures_changed = false)
    {
        for (const auto& root : interested_roots(entry)) {
            mark_root(root);
            if (entry.state == Coverage_state::FAILED) {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
            }
            if (failures_changed || entry.state == Coverage_state::FAILED) {
                mark_read(root, true, entry.revision);
            }
        }
    }

    void mark_read(const std::shared_ptr<Root>& root, bool failures_changed = false,
        uint64_t known_native_revision = 0)
    {
        const auto owner = root->owner.lock();
        if (!owner || !owner->active) {
            return;
        }
        auto status = root->read_status;
        if (failures_changed) {
            status = coverage_status(*root);
        }
        else
        if (status.state != Coverage_state::FAILED) {
            status = {root->covered && root->expansion_complete && root->content->native_id != 0 &&
                root->guard && root->guard->native_id != 0
                ? Coverage_state::COVERED : Coverage_state::PENDING, {}};
        }
        if (status.state == Coverage_state::FAILED) {
            root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
        }
        // Native loss becomes visible before retirement and the later logical
        // reconciliation. Its revision must invalidate captures at that same boundary.
        const auto revision = std::max({root->read_revision, root->revision, known_native_revision});
        if (root->read_status.state != status.state || root->read_status.diagnostic != status.diagnostic ||
            root->read_revision != revision)
        {
            root->read_status = std::move(status);
            root->read_revision = revision;
            m_read_dirty_clients.insert(owner->id);
        }
    }

    std::shared_ptr<const Read_view> read_view(uint64_t client) const
    {
        const std::lock_guard lock(m_read_mutex);
        return m_read_views.value(client);
    }

    void publish_reads()
    {
        const auto pending = std::exchange(m_read_dirty_clients, {});
        for (const auto id : pending) {
            const auto client = m_clients.value(id);
            if (!client) {
                continue;
            }
            auto view = std::make_shared<Read_view>();
            view->requested = client->requested != 0;
            view->interests = client->interest_keys;
            view->root_indices = client->root_indices;
            view->roots.reserve(client->roots.size());
            for (const auto& root : client->roots) {
                view->roots.append({root->key, root->read_status, root->read_revision});
            }
            std::shared_ptr<const Read_view> retired;
            {
                const std::lock_guard lock(m_read_mutex);
                retired = std::exchange(m_read_views[id], std::move(view));
            }
        }
    }

    void unlock(std::unique_lock<std::mutex>& lock)
    {
        // Known loss and incomplete plans must be visible before maintenance
        // releases its lock, including a potentially slow native retirement.
        publish_reads();
        lock.unlock();
    }

    void set_native_id(Entry& entry, uint64_t id)
    {
#ifdef Q_OS_WIN
        if (!entry.physical)
#endif
        {
            m_resources.covered_logical_directories += int(id != 0) - int(entry.native_id != 0);
        }
        entry.native_id = id;
    }

    void retire_later(const std::shared_ptr<Entry>& entry)
    {
        if (entry) {
            m_retirement_candidates.insert(entry->key, entry);
        }
    }

    void retire_node(const std::shared_ptr<Root::Node>& node)
    {
        if (node->active) {
            node->active->store(false);
        }
        m_scans.remove(std::exchange(node->scan, 0));
        retire_later(node->entry);
    }

    void schedule_parent(const std::shared_ptr<Root>& root, Clock::time_point when)
    {
        m_parent_due.erase({root->parent_retry_at, root->id});
        root->parent_retry_at = when;
        m_parent_due.emplace(std::make_pair(when, root->id), root);
    }

    void schedule_scan_retry(const std::shared_ptr<Root>& root, Clock::time_point when)
    {
        m_scan_due.erase({root->scan_retry_at, root->id});
        root->scan_retry_at = when;
        if (when != Clock::time_point::max()) {
            m_scan_due.emplace(std::make_pair(when, root->id), root);
        }
    }

    void schedule_native(Entry& entry, Clock::time_point when)
    {
#ifdef Q_OS_WIN
        if (!entry.physical) {
            return;
        }
        const auto owner = m_windows_anchors.value(entry.key);
#else
        const auto owner = m_entries.value(entry.key);
#endif
        m_native_due.erase({entry.native_due, &entry});
        entry.native_due = when;
        if (owner && when != Clock::time_point::max()) {
            m_native_due.emplace(std::make_pair(when, &entry), owner);
        }
    }

#ifdef Q_OS_WIN
    void schedule_identity(Entry& entry, Clock::time_point when = {})
    {
        m_identity_due.erase({entry.validate_at, &entry});
        entry.validate_at = when;
        if (when != Clock::time_point::max()) {
            m_identity_due.emplace(std::make_pair(when, &entry), m_entries.value(entry.key));
        }
    }

    void add_boundary(const std::shared_ptr<Entry>& entry)
    {
        if (entry->boundary_reasons++ == 0) {
            entry->anchor_input = true;
            schedule_identity(*entry);
            ++m_windows_plan_generation;
        }
    }

    void remove_boundary(const std::shared_ptr<Entry>& entry)
    {
        if (entry && --entry->boundary_reasons == 0) {
            entry->anchor_input = false;
            schedule_identity(*entry);
            ++m_windows_plan_generation;
        }
    }
#endif

    void refresh_root_resources(const std::shared_ptr<Root>& root)
    {
        if (!root->resources_dirty) {
            return;
        }
        m_resources.scan_pending -= root->scan_pending;
        m_resources.scan_failed -= root->scan_failed;
        root->scan_pending = root->scan_failed = 0;
        root->node_budget_refused = false;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (const auto owner = root->owner.lock()) {
            owner->maintenance.resource_nodes += uint64_t(root->nodes.size());
        }
#endif
        for (const auto& node : root->nodes) {
            root->scan_pending += !node->complete;
            root->scan_failed += !node->error.isEmpty();
            root->node_budget_refused |= node->budget_refused;
        }
        m_resources.scan_pending += root->scan_pending;
        m_resources.scan_failed += root->scan_failed;
        root->resources_dirty = false;
    }

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    void count_entry_maintenance(const Entry& entry, uint64_t Maintenance_counts::*member)
    {
        const auto roots = interested_roots(entry);
        if (std::any_of(roots.cbegin(), roots.cend(), [&](const auto& root) {
                return root->content.get() == &entry || root->guard.get() == &entry;
            }))
        {
            return;
        }
        std::set<uint64_t> clients;
        for (const auto& root : roots) {
            if (const auto owner = root->owner.lock(); owner && clients.insert(owner->id).second) {
                ++(owner->maintenance.*member);
            }
        }
    }
#endif

    void retire_root(const std::shared_ptr<Root>& root)
    {
        retire_later(root->content);
        retire_later(root->guard);
        for (const auto& node : root->nodes) {
            retire_node(node);
        }
        m_resources.scan_pending -= root->scan_pending;
        m_resources.scan_failed -= root->scan_failed;
        root->scan_pending = root->scan_failed = 0;
        m_parent_due.erase({root->parent_retry_at, root->id});
        m_scan_due.erase({root->scan_retry_at, root->id});
        m_dirty_roots.remove(root->id);
        m_reconcile_roots.remove(root->id);
        m_roots.remove(root->id);
#ifdef Q_OS_WIN
        m_retirement_blocked_roots.remove(root->id);
        remove_boundary(root->content);
        remove_boundary(root->guard);
#endif
    }

    struct Notification
    {
        std::shared_ptr<Client> client;
        Native_batch batch;
    };

    struct Scan
    {
        std::weak_ptr<Root> root;
        std::weak_ptr<Root::Node> node;
        uint64_t revision = 0;
        bool first_result = true;
    };

    explicit Impl(direct_limits_t limits)
    :
        m_limits(limits)
    {
        m_plan_budget->limit = limits.plan_bytes;
    }

    void stop()
    {
        {
            const std::lock_guard lock(m_mutex);
            m_stopped = true;
            m_backend.wake();
            m_changed.notify_all();
        }
        if (m_worker.get_id() == std::this_thread::get_id()) {
            // A standalone native callback may clear its own watcher. The worker
            // retains this state until that callback and its loop have returned.
            m_worker.detach();
        }
        else {
            m_worker.join();
        }
        m_scanner->stop();
    }

    std::shared_ptr<Entry> entry(const QString& path, const path_name::Key& key)
    {
        if (const auto existing = m_entries.value(key)) {
            return existing;
        }
        auto result = std::make_shared<Entry>();
        result->path = path;
        result->key = key;
        result->revision = s_next_coverage_revision.fetch_add(1);
        m_entries.insert(key, result);
        retire_later(result);
#ifdef Q_OS_WIN
        schedule_identity(*result);
        m_binding_entries.insert(key, result);
#else
        schedule_native(*result, {});
#endif
        return result;
    }

    std::shared_ptr<Plan_charge> reserve_plan(size_t bytes, QString& failure)
    {
        try {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            if (native_test_hooks::plan_allocation_failure.load()) {
                throw std::bad_alloc();
            }
#endif
            auto charge = std::make_shared<Plan_charge>();
            charge->budget = m_plan_budget;
            size_t used = m_plan_budget->used.load();
            do {
                if (bytes > std::numeric_limits<size_t>::max() - used) {
                    failure = QStringLiteral("Directory observation plan accounting overflow");
                    return {};
                }
                const size_t limit = m_plan_budget->limit;
                if (m_limits.bounded_workload && (bytes > limit || used > limit - bytes)) {
                    return {};
                }
            } while (!m_plan_budget->used.compare_exchange_weak(used, used + bytes));
            charge->bytes = bytes;
            return charge;
        }
        catch (const std::bad_alloc&) {
            failure = QStringLiteral("Directory observation plan allocation failed");
            return {};
        }
    }

    std::shared_ptr<Root::Node> make_node(const std::shared_ptr<Root>& root,
        const std::shared_ptr<Entry>& entry, int depth,
        std::shared_ptr<path_name::Policy_epoch> policy, QString& failure)
    {
        // Charge all owning key copies conservatively, even where Qt currently
        // shares their storage. Include map/set nodes and allocator metadata.
        const auto text_bytes = [](const QString& text) {
            return size_t(64) + size_t(text.capacity() + 1) * sizeof(QChar);
        };
        const size_t key_bytes = directory_plan_key_bytes(entry->key);
        const size_t bytes = sizeof(Root::Node) + sizeof(Entry) + 256 +
            text_bytes(entry->path) + 3 * key_bytes + directory_plan_policy_bytes(entry->path);
        auto charge = reserve_plan(bytes, failure);
        if (!charge) {
            return {};
        }
        try {
            const auto node = std::make_shared<Root::Node>();
            node->charge = std::move(charge);
            node->entry = entry;
            node->interest.set(entry, root);
            node->policy = std::move(policy);
            node->depth = depth;
            return node;
        }
        catch (const std::bad_alloc&) {
            failure = QStringLiteral("Directory observation plan allocation failed");
            return {};
        }
    }

    void update_clients()
    {
        const auto clients = std::exchange(m_dirty_clients, {});
        for (const auto id : clients) {
            const auto client = m_clients.value(id);
            if (!client) {
                continue;
            }
            if (client->requested == client->applied) {
                continue;
            }
            QList<std::shared_ptr<Root>> roots;
            for (const auto& specification : client->paths) {
                const auto& path = specification.path;
                const auto key = client->policy->key(path);
                std::shared_ptr<Root> root;
                auto cause = Reconciliation_cause::INITIAL_ADMISSION;
                for (const auto& previous : client->roots) {
                    if (previous->key != key) {
                        continue;
                    }
                    const bool same_scope = previous->policy == client->policy &&
                        previous->mode == client->mode &&
                        previous->maximum_depth == specification.maximum_depth;
                    if (same_scope && previous->eligibility_generation == client->eligibility_generation) {
                        root = previous;
                        break;
                    }
                    if (!previous->covered) {
                        // Replacing an unfinished plan cannot change the cause
                        // of the readback it still owes.
                        cause = previous->cause;
                    }
                    else
                    if (same_scope && previous->content->native_id != 0 &&
                        previous->guard && previous->guard->native_id != 0)
                    {
                        cause = Reconciliation_cause::CONSUMER_RECONCILIATION;
                    }
                    else {
                        cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                    }
                }
                if (!live(root)) {
                    root = std::make_shared<Root>();
                    root->id = ++m_next_root;
                    root->owner = client;
                    root->path = path;
                    root->key = key;
                    root->policy = client->policy;
                    root->content = entry(path, key);
                    root->content_interest.set(root->content, root);
#ifdef Q_OS_WIN
                    add_boundary(root->content);
#endif
                    root->mode = client->mode;
                    root->maximum_depth = specification.maximum_depth;
                    root->filter = client->filter;
                    root->eligibility_generation = client->eligibility_generation;
                    root->cause = cause;
                    if (root->mode != Watch_mode::DIRECT) {
                        root->expansion_complete = false;
                    }
                    m_roots.insert(root->id, root);
                    schedule_parent(root, {});
                    mark_root(root);
                    mark_read(root, true);
                }
                if (!roots.contains(root)) {
                    roots.append(std::move(root));
                }
            }
            for (const auto& previous : client->roots) {
                if (!roots.contains(previous)) {
                    for (const auto& node : previous->nodes) {
                        if (node->active) {
                            node->active->store(false);
                        }
                    }
                    // Retained physical reasons do not need the superseded
                    // callback. Running jobs own/drain their immutable snapshot.
                    previous->filter = {};
                    if (previous->mode == Watch_mode::DIRECT || !previous->nodes.isEmpty()) {
                        client->retiring_roots.append(previous);
                        m_retiring_clients.insert(client->id);
                    }
                    else {
                        retire_root(previous);
                    }
                }
            }
            // Membership is unchanged by ordinary coverage publication. Qt's
            // shared map keeps that immutable index with each published view.
            QMap<path_name::Key, QList<qsizetype>> root_indices;
            for (qsizetype index = 0; index < roots.size(); ++index) {
                root_indices[path_name::matching_bucket(roots[index]->key)].append(index);
            }
            client->roots = std::move(roots);
            client->root_indices = std::move(root_indices);
            m_read_dirty_clients.insert(client->id);
            client->initial = true;
            client->prepared = client->requested;
            m_attempt_clients.insert(client->id);
        }
    }

    bool update_parents(std::unique_lock<std::mutex>& lock)
    {
        bool changed = false;
        const auto due = Clock::now();
        while (!m_parent_due.empty() && m_parent_due.begin()->first.first <= due) {
            const auto root = m_parent_due.begin()->second.lock();
            m_parent_due.erase(m_parent_due.begin());
            if (!live(root)) {
                continue;
            }
#ifdef Q_OS_WIN
            const auto& current_guard = root->guard;
            if (current_guard && current_guard->identity_known && current_guard->native_id != 0 &&
                current_guard->state == Coverage_state::COVERED &&
                path_name::matches_key(QFileInfo(root->path).absolutePath(), current_guard->key))
            {
                // The admitted immediate parent already has native coverage and
                // periodic boundary identity validation. Loss or relevant topology
                // schedules this root again; an ancestor fallback still needs the
                // recovery search to discover a newly created nearer parent.
                schedule_parent(root, Clock::now() + k_retry_interval);
                continue;
            }
#endif
            unlock(lock);
            const auto parent = recovery_parent(root->path);
            const auto key = root->policy->key(parent);
            lock.lock();
            if (!live(root)) {
                continue;
            }
            const auto guard = entry(parent, key);
            changed |= root->guard != guard;
#ifdef Q_OS_WIN
            if (root->guard != guard) {
                remove_boundary(root->guard);
                add_boundary(guard);
            }
#endif
            if (root->guard != guard) {
                retire_later(root->guard);
                const bool failures_changed = guard->state == Coverage_state::FAILED ||
                    (root->guard && root->guard->state == Coverage_state::FAILED);
                root->guard = guard;
                root->guard_interest.set(guard, root);
                mark_root(root);
                mark_read(root, failures_changed);
            }
            schedule_parent(root, Clock::now() + k_retry_interval);
        }
        return changed;
    }

    void release_replaced_roots()
    {
        bool retiring = false;
        const auto clients = m_retiring_clients;
        for (const auto id : clients) {
            const auto client = m_clients.value(id);
            if (!client) {
                m_retiring_clients.erase(id);
                continue;
            }
            if (std::all_of(client->roots.cbegin(), client->roots.cend(),
                [](const auto& root) {
#ifdef Q_OS_WIN
                    return root->content->native_id != 0 && root->guard &&
                        root->guard->native_id != 0 && root->expansion_complete;
#else
                    return root->covered;
#endif
                }))
            {
                m_work_pending |= !client->retiring_roots.isEmpty();
                for (const auto& root : client->retiring_roots) {
                    retire_root(root);
                }
                client->retiring_roots.clear();
                m_retiring_clients.erase(client->id);
            }
            retiring |= !client->retiring_roots.isEmpty();
        }
        if (!retiring) {
            return;
        }
        size_t registrations = m_backend.allocated_registrations();
        size_t bytes = m_backend.allocated_bytes();
        bool overflow = false;
#ifndef Q_OS_WIN
        std::set<const Entry*> required;
        for (const auto& client : m_clients) {
            for (const auto& root : client->roots) {
                required.insert(root->content.get());
                if (root->guard) {
                    required.insert(root->guard.get());
                }
                for (const auto& node : root->nodes) {
                    required.insert(node->entry.get());
                }
            }
        }
        for (const auto* entry : required) {
            if (entry->native_id == 0) {
                overflow |= !add_usage(registrations, 1);
                overflow |= !add_usage(bytes, Direct_native_backend::registration_bytes(entry->path));
            }
        }
#endif
        bool plan_pressure = false;
#ifdef Q_OS_WIN
        plan_pressure = m_windows_plan_budget_refused || !m_identity_budget_refused.empty();
#endif
        for (const auto& client : m_clients) {
            for (const auto& root : client->roots) {
                refresh_root_resources(root);
                plan_pressure |= root->budget_refused || root->node_budget_refused;
            }
        }
        if (overflow || plan_pressure || (m_limits.bounded_workload &&
            (registrations > m_limits.registrations || bytes > m_limits.bytes)))
        {
            // Only obsolete reasons are dropped. Entries still required by any
            // live interest stay referenced, and cancellation buffers remain
            // charged by the native backend until retirement completes.
            for (const auto& client : m_clients) {
                for (const auto& root : client->roots) {
                    root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                }
                m_work_pending |= !client->retiring_roots.isEmpty();
                for (const auto& root : client->retiring_roots) {
                    retire_root(root);
                }
                client->retiring_roots.clear();
                m_retiring_clients.erase(client->id);
            }
        }
    }

    void retire_entries(std::unique_lock<std::mutex>& lock)
    {
        const auto candidates = std::exchange(m_retirement_candidates, {});
        for (auto it = candidates.cbegin(); it != candidates.cend(); ++it) {
            // The queue is weak. Only the registry map may own a retired entry.
            if (it.value().use_count() != 1) {
                continue;
            }
            const auto entry = it.value().lock();
            if (!entry || entry->interests) {
                continue;
            }
            const auto native_id = entry->native_id;
            set_native_id(*entry, 0);
#ifdef Q_OS_WIN
            m_identity_due.erase({entry->validate_at, entry.get()});
            m_binding_entries.remove(entry->key);
            m_identity_budget_refused.erase(entry.get());
            if (entry->identity_known) {
                erase_windows_route(m_windows_routes, entry->physical_key, entry.get());
            }
#else
            m_native_due.erase({entry->native_due, entry.get()});
            m_native_entries.remove(native_id);
#endif
            m_entries.remove(it.key());
#ifndef Q_OS_WIN
            unlock(lock);
            m_backend.retire(native_id);
            lock.lock();
#else
            Q_UNUSED(native_id);
#endif
        }
#ifdef Q_OS_WIN
        retire_windows_anchors(lock);
#endif
    }

    void lose(Entry& entry, const QString& failure, std::unique_lock<std::mutex>& lock,
        Coverage_state state = Coverage_state::FAILED)
    {
        const bool was_failed = entry.state == Coverage_state::FAILED;
        const QString previous_failure = entry.failure;
        const auto native_id = entry.native_id;
        set_native_id(entry, 0);
        entry.state = native_id != 0 ? Coverage_state::FAILED : state;
#ifdef Q_OS_WIN
        if (entry.physical) {
            m_native_entries.remove(native_id);
            entry.failure = entry.state == Coverage_state::FAILED ? failure : QString{};
            entry.revision = s_next_coverage_revision.fetch_add(1);
            entry.retry_at = Clock::now() + k_retry_interval;
            schedule_native(entry, entry.retry_at);
            for (const auto& logical : m_entries) {
                if (logical->anchor.get() == &entry) {
                    schedule_identity(*logical);
                    lose(*logical, failure, lock);
                }
            }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            publish_reads();
            if (m_maintenance_observer) {
                m_maintenance_observer(Maintenance_stage::RETIREMENT);
            }
#endif
            unlock(lock);
            m_backend.retire(native_id);
            lock.lock();
            if (m_backend.retirement_pending(native_id)) {
                m_windows_retiring.insert(native_id, m_windows_anchors.value(entry.key));
            }
            return;
        }
#else
        m_native_entries.remove(native_id);
#endif
        entry.failure = entry.state == Coverage_state::FAILED ? failure : QString{};
        const bool entry_failure_changed = was_failed != (entry.state == Coverage_state::FAILED) ||
            (was_failed && previous_failure != entry.failure);
        entry.revision = s_next_coverage_revision.fetch_add(1);
        entry.retry_at = Clock::now() + k_retry_interval;
        schedule_native(entry, entry.retry_at);
#ifdef Q_OS_WIN
        m_binding_entries.insert(entry.key, m_entries.value(entry.key));
#endif
        for (const auto& root : interested_roots(entry)) {
            bool failures_changed = entry_failure_changed;
            // A retained descendant can fail before a replacement plan has
            // rediscovered it. First Windows identity binding is only PENDING.
            if (entry.state == Coverage_state::FAILED) {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
            }
            const auto read = qScopeGuard([&] { mark_read(root, failures_changed, entry.revision); });
            mark_root(root);
            if (root->content.get() == &entry || root->guard.get() == &entry) {
                schedule_parent(root, {});
            }
            const auto node = root ? root->nodes.value(entry.key) : nullptr;
            if (!node) {
                continue;
            }
            if (node->active) {
                node->active->store(false);
            }
            m_scans.remove(std::exchange(node->scan, 0));
            node->complete = false;
            node->children.clear();
            for (auto it = root->nodes.begin(); it != root->nodes.end();) {
                if (it.value() != node && path_name::is_ancestor_of_key(entry.path, it.key())) {
                    failures_changed |= !it.value()->error.isEmpty() ||
                        it.value()->entry->state == Coverage_state::FAILED;
                    retire_node(it.value());
                    it = root->nodes.erase(it);
                }
                else {
                    ++it;
                }
            }
            root->expansion_complete = false;
            mark_root(root);
        }
#ifndef Q_OS_WIN
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        publish_reads();
        if (m_maintenance_observer) {
            m_maintenance_observer(Maintenance_stage::RETIREMENT);
        }
#endif
        unlock(lock);
        m_backend.retire(native_id);
        lock.lock();
#else
        Q_UNUSED(native_id);
#endif
    }

    size_t plan_bytes() const
    {
        return m_plan_budget->used.load();
    }

    void request_scan(const std::shared_ptr<Root>& root, const std::shared_ptr<Root::Node>& node,
        bool complete_detail = false)
    {
#ifdef Q_OS_WIN
        // A recursive ancestor still captures an already admitted directory
        // while its precise topology changes are enumerated. New nodes and
        // lost-detail/native-generation scans must establish coverage first.
        node->rescan_covered = complete_detail && (node->complete || node->rescan_covered) &&
            node->entry->native_id != 0 && node->error.isEmpty() && !node->filter_pending;
#else
        Q_UNUSED(complete_detail);
#endif
        if (node->scan != 0) {
            node->again = true;
        }
        node->complete = false;
        if (!node->rescan_covered) {
            root->expansion_complete = false;
            mark_read(root);
        }
        node->retry_at = {};
        mark_root(root);
    }

#ifdef Q_OS_WIN
    bool retire_missing_descendants(const std::shared_ptr<Entry>& missing,
        std::unique_lock<std::mutex>& lock)
    {
        bool changed = false;
        for (const auto& root : interested_roots(*missing)) {
            auto removed = root->nodes.value(missing->key);
            if (!removed || removed->entry == root->content || removed->entry == root->guard) {
                continue;
            }
            // A populated subtree can disappear in one operation. Walk its
            // admitted parents until a surviving captured directory proves
            // where ordinary membership readback can safely resume.
            while (live(root)) {
                auto parent_key = removed->entry->key;
                if (parent_key.components.isEmpty()) {
                    break;
                }
                parent_key.components.removeLast();
                const auto parent = root->nodes.value(parent_key);
                if (!parent) {
                    break;
                }
                const auto entry = parent->entry;
                const auto revision = entry->revision;
                const auto anchor = entry->anchor;
                const auto native_id = entry->native_id;
                windows_directory_identity_t identity{};
                QString physical_path;
                QString failure;
                bool parent_missing = false;
                unlock(lock);
                const bool known = capture_windows_directory_identity(
                    entry->path, identity, physical_path, failure, &parent_missing);
                lock.lock();
                if (!live(root) || root->nodes.value(removed->entry->key) != removed ||
                    root->nodes.value(parent_key) != parent || entry->revision != revision)
                {
                    break;
                }
                if (parent_missing && entry != root->content && entry != root->guard) {
                    removed = parent;
                    continue;
                }
                if (!known || !entry->identity_known || !anchor || anchor != entry->anchor ||
                    native_id == 0 || entry->native_id != native_id || anchor->native_id != native_id ||
                    anchor->state != Coverage_state::COVERED || entry->anchor_revision != anchor->revision ||
                    !same_windows_directory_identity(identity, entry->identity) ||
                    !path_name::matches_key(physical_path, entry->physical_key))
                {
                    break;
                }
                // The old parent result may still contain the removed child.
                // Cancel it before pruning so it cannot readmit a stale node.
                if (parent->active) {
                    parent->active->store(false);
                }
                m_scans.remove(std::exchange(parent->scan, 0));
                parent->again = false;
                parent->children.erase(removed->entry->key);
                parent->seen.erase(removed->entry->key);
                const auto path = removed->entry->path;
                bool failures_changed = false;
                for (auto it = root->nodes.begin(); it != root->nodes.end();) {
                    if (path_name::is_ancestor_of_key(path, it.key())) {
                        failures_changed |= !it.value()->error.isEmpty() ||
                            it.value()->entry->state == Coverage_state::FAILED;
                        retire_node(it.value());
                        it = root->nodes.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
                request_scan(root, parent, true);
                mark_read(root, failures_changed);
                changed = true;
                break;
            }
        }
        return changed;
    }
#endif

    void apply_scans(std::unique_lock<std::mutex>& lock)
    {
        for (int processed = 0; !m_scan_results.isEmpty() && processed != 8; ++processed) {
            auto result = m_scan_results.takeFirst();
            m_scan_result_bytes -= result.bytes;
            m_changed.notify_all();
            const auto request = m_scans.value(result.id);
            const auto root = request.root.lock();
            const auto node = request.node.lock();
            if (!live(root) || !node || node->scan != result.id) {
                m_scans.remove(result.id);
                continue;
            }
            const QString previous_error = node->error;
            bool failures_changed = false;
            const auto read = qScopeGuard([&] {
                mark_read(root, failures_changed || node->error != previous_error);
            });
            if (request.revision != node->entry->revision) {
                // A new anchor or registration supersedes this attempt without
                // establishing that the directory itself changed. Re-enumerate
                // under the current revision and retain any real earlier error.
                node->active->store(false);
                node->scan = 0;
                m_scans.remove(result.id);
                node->again = false;
                request_scan(root, node);
                continue;
            }
            QString identity_error;
            bool missing = false;
            unlock(lock);
            const bool same_identity = entry_identity_matches(*node->entry, identity_error, &missing);
            lock.lock();
            if (!live(root)) {
                m_scans.remove(result.id);
                continue;
            }
            if (!same_identity) {
#ifdef Q_OS_WIN
                if (missing) {
                    retire_missing_descendants(node->entry, lock);
                    if (!live(root) || root->nodes.value(node->entry->key) != node) {
                        m_scans.remove(result.id);
                        continue;
                    }
                }
                schedule_identity(*node->entry);
#endif
                node->active->store(false);
                node->scan = 0;
                m_scans.remove(result.id);
                node->error = identity_error.isEmpty()
                    ? QStringLiteral("Directory identity changed during expansion") : identity_error;
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                node->retry_at = Clock::now() + k_retry_interval;
                mark_root(root);
                continue;
            }
            if (result.policy) {
                node->policy = result.policy;
            }
            const auto scan = m_scans.find(result.id);
            if (scan == m_scans.end() || node->scan != result.id) {
                continue;
            }
            // Partial chunks can change failure/filter state without adding a
            // child. Reconsider this root before the final chunk arrives too.
            mark_root(root);
            const bool first_result = std::exchange(scan->first_result, false);
            if (first_result && result.error.isEmpty() && !result.filter_pending) {
                node->error.clear();
            }
            for (const auto& candidate : result.directories) {
                const auto& path = candidate.path;
                const auto& key = candidate.key;
                if (root->nodes.contains(key)) {
                    try {
                        node->seen.insert(key);
                    }
                    catch (const std::bad_alloc&) {
                        node->budget_refused = true;
                        node->error = QStringLiteral("Directory observation plan allocation failed");
                    }
                    continue;
                }
                QString failure = QStringLiteral("Directory expansion memory budget exhausted");
                try {
                    const auto child = make_node(root, entry(path, key), node->depth + 1, candidate.policy, failure);
                    if (child) {
                        node->seen.insert(key);
                        try {
                            root->nodes.insert(key, child);
                        }
                        catch (...) {
                            node->seen.erase(key);
                            throw;
                        }
                        root->expansion_complete = false;
                        failures_changed |= child->entry->state == Coverage_state::FAILED;
                        mark_root(root);
                        continue;
                    }
                }
                catch (const std::bad_alloc&) {
                    failure = QStringLiteral("Directory observation plan allocation failed");
                }
                node->budget_refused = true;
                node->error = std::move(failure);
            }
            if (!result.error.isEmpty()) {
                node->error = result.error;
            }
            node->filter_pending = result.filter_pending;
            if (node->filter_pending) {
                root->expansion_complete = false;
            }
            if (!node->error.isEmpty()) {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
            }
            if (!result.complete) {
                continue;
            }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            ++root->owner.lock()->expansions;
#endif
            m_scans.remove(result.id);
            node->scan = 0;
            if (result.error.isEmpty() && !result.filter_pending) {
                std::vector<path_name::Key> removed;
                std::set_difference(node->children.begin(), node->children.end(),
                    node->seen.begin(), node->seen.end(), std::back_inserter(removed));
                for (const auto& old : removed) {
                    const auto obsolete = root->nodes.value(old);
                    if (!obsolete) {
                        continue;
                    }
                    const auto old_path = obsolete->entry->path;
                    for (auto it = root->nodes.begin(); it != root->nodes.end();) {
                        if (it.value() != node && path_name::is_ancestor_of_key(old_path, it.key()))
                        {
                            failures_changed |= !it.value()->error.isEmpty() ||
                                it.value()->entry->state == Coverage_state::FAILED;
                            retire_node(it.value());
                            it = root->nodes.erase(it);
                        }
                        else {
                            ++it;
                        }
                    }
                }
                node->children = node->seen;
            }
            node->complete = node->error.isEmpty() && !node->filter_pending && !node->again;
            node->again = false;
            node->retry_at = node->error.isEmpty() && !node->filter_pending
                ? Clock::time_point{} : Clock::now() + k_retry_interval;
            mark_root(root);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            mark_read(root, failures_changed || node->error != previous_error);
            publish_reads();
            if (m_maintenance_observer) {
                m_maintenance_observer(Maintenance_stage::SCAN_APPLIED);
            }
#endif
        }
        if (!m_scan_results.isEmpty()) {
            m_backend.wake();
        }
    }

    void start_scans()
    {
        const auto pending = std::exchange(m_dirty_roots, {});
        auto next = pending.upperBound(m_scan_cursor);
        for (qsizetype visited = 0; visited != pending.size(); ++visited) {
            if (next == pending.end()) {
                next = pending.begin();
            }
            const auto root_id = next.key();
            const auto root = next.value().lock();
            ++next;
            if (!live(root) || root->mode == Watch_mode::DIRECT) {
                continue;
            }
            const QString previous_expansion_failure = root->expansion_failure;
            bool failures_changed = false;
            const auto read = qScopeGuard([&] {
                mark_read(root, failures_changed || root->expansion_failure != previous_expansion_failure);
            });
            auto retry_at = Clock::time_point::max();
            schedule_scan_retry(root, retry_at);
            if (root->nodes.isEmpty()) {
                if (Clock::now() < root->expansion_retry_at) {
                    schedule_scan_retry(root, root->expansion_retry_at);
                    continue;
                }
                QString failure = QStringLiteral("Directory expansion memory budget exhausted");
                std::shared_ptr<Root::Node> node;
                try {
                    node = make_node(root, root->content, 0, root->policy, failure);
                    if (node) {
                        root->nodes.insert(root->key, node);
                    }
                }
                catch (const std::bad_alloc&) {
                    node.reset();
                    failure = QStringLiteral("Directory observation plan allocation failed");
                }
                if (!node) {
                    root->budget_refused = true;
                    root->expansion_failure = std::move(failure);
                    root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                    root->expansion_retry_at = Clock::now() + k_retry_interval;
                    schedule_scan_retry(root, root->expansion_retry_at);
                    mark_root(root);
                    continue;
                }
                root->budget_refused = false;
                root->expansion_failure.clear();
            }
            bool complete = true;
            int running = m_scans.isEmpty() ? 0 : int(std::count_if(root->nodes.cbegin(), root->nodes.cend(),
                [](const auto& node) { return node->scan != 0; }));
            for (const auto& node : root->nodes) {
                if (node->observed_revision != node->entry->revision) {
                    node->observed_revision = node->entry->revision;
                    request_scan(root, node);
                }
                if (node->entry->native_id == 0) {
                    complete = false;
                    continue;
                }
                if (root->mode == Watch_mode::DISCOVERY_RECURSIVE && node->depth >= root->maximum_depth) {
                    node->complete = true;
                }
                if (node->complete) {
                    continue;
                }
                complete &= node->rescan_covered && node->error.isEmpty() && !node->filter_pending;
                if (node->scan != 0 || running >= k_root_scan_concurrency) {
                    continue;
                }
                if (Clock::now() < node->retry_at) {
                    retry_at = std::min(retry_at, node->retry_at);
                    continue;
                }
                QString failure = QStringLiteral("Directory scan memory budget exhausted");
                auto job_charge = reserve_plan(directory_scan_job_bytes(root->path, node->entry->path), failure);
                if (!job_charge) {
                    node->budget_refused = true;
                    failures_changed |= node->error != failure;
                    node->error = std::move(failure);
                    root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                    node->retry_at = Clock::now() + k_retry_interval;
                    retry_at = std::min(retry_at, node->retry_at);
                    continue;
                }
                const auto id = ++m_next_scan;
                failure.clear();
                try {
                    auto active = std::make_shared<std::atomic_bool>(true);
                    m_scans.insert(id, {root, node, node->entry->revision});
                    if (m_scanner->submit({id, root->owner.lock()->id, node->charge, std::move(job_charge),
                            root->path, node->entry->path, root->filter, active, node->policy,
                            m_limits.bounded_workload}, failure))
                    {
                        m_scan_cursor = root_id;
                        ++running;
                        node->scan = id;
                        node->active = std::move(active);
                        node->budget_refused = false;
                        node->seen.clear();
                        continue;
                    }
                }
                catch (const std::bad_alloc&) {
                    failure = QStringLiteral("Directory observation plan allocation failed");
                }
                m_scans.remove(id);
                node->budget_refused = true;
                failures_changed |= node->error != failure;
                node->error = std::move(failure);
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                node->retry_at = Clock::now() + k_retry_interval;
                retry_at = std::min(retry_at, node->retry_at);
            }
            schedule_scan_retry(root, retry_at);
            refresh_root_resources(root);
            if (root->expansion_complete != complete) {
                root->expansion_complete = complete;
                mark_root(root);
                m_work_pending = true;
            }
        }
    }

#ifdef Q_OS_WIN
    bool retire_windows_anchors(std::unique_lock<std::mutex>& lock)
    {
        bool changed = false;
        for (auto it = m_windows_anchors.begin(); it != m_windows_anchors.end();) {
            if (it.value().use_count() != 1) {
                ++it;
                continue;
            }
            const auto id = it.value()->native_id;
            const auto retired = it.value();
            m_native_entries.remove(id);
            m_native_due.erase({retired->native_due, retired.get()});
            it = m_windows_anchors.erase(it);
            changed = true;
            unlock(lock);
            m_backend.retire(id);
            lock.lock();
            if (m_backend.retirement_pending(id)) {
                m_windows_retiring.insert(id, retired);
            }
        }
        for (auto it = m_windows_retiring.begin(); it != m_windows_retiring.end();) {
            if (!m_backend.retirement_pending(it.key())) {
                it = m_windows_retiring.erase(it);
                changed = true;
            }
            else {
                ++it;
            }
        }
        if (changed) {
            for (const auto& weak : m_retirement_blocked_roots) {
                if (const auto root = weak.lock(); live(root)) {
                    mark_root(root);
                }
            }
        }
        return changed;
    }

    bool validate_windows_directories(std::unique_lock<std::mutex>& lock)
    {
        bool changed = false;
        if (m_identity_round == Clock::time_point{}) {
            m_identity_round = Clock::now();
        }
        int operations = 0;
        while (!m_identity_due.empty() && m_identity_due.begin()->first.first <= m_identity_round) {
            if (operations == k_native_operations_per_turn) {
                m_backend.wake();
                return changed;
            }
            const auto entry = m_identity_due.begin()->second.lock();
            m_identity_due.erase(m_identity_due.begin());
            if (!entry) {
                continue;
            }
            ++operations;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            count_entry_maintenance(*entry, &Maintenance_counts::identity_candidates);
#endif
            windows_directory_identity_t identity{};
            QString path;
            QString failure;
            bool missing = false;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            const bool capture_gap = !entry->anchor_input &&
                native_test_hooks::windows_pause_uncovered_identity_requested.exchange(false);
            if (capture_gap) {
                // Force the capture-before-arm ordering without invalidating
                // the logical snapshot whose continuity the test exercises.
                for (const auto& anchor : m_windows_desired) {
                    const auto native_id = std::exchange(anchor->native_id, 0);
                    m_native_entries.remove(native_id);
                    anchor->retry_at = {};
                    schedule_native(*anchor, {});
                    unlock(lock);
                    m_backend.retire(native_id);
                    lock.lock();
                }
            }
#endif
            unlock(lock);
            bool known = capture_windows_directory_identity(entry->path, identity, path, failure, &missing);
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            ++native_test_hooks::windows_identity_validations;
            if (!entry->anchor_input) {
                ++native_test_hooks::windows_descendant_identity_validations;
            }
            if (capture_gap) {
                native_test_hooks::windows_uncovered_identity_pause_reached.store(true);
                while (!native_test_hooks::windows_uncovered_identity_pause_released.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
#endif
            // This short-lived policy owns only this resolved spelling. It does
            // not accumulate historical names across rename/create churn.
            const auto physical_key = !known ? path_name::Key{} :
                (entry->identity_known && path == entry->physical_path ? entry->physical_key :
                    path_name::Policy_epoch{}.key(path));
            lock.lock();
            if (missing) {
                changed |= retire_missing_descendants(entry, lock);
            }
            if (known && (!entry->identity_known || entry->physical_key != physical_key)) {
                // The previous resolved spelling is obsolete. Its storage can
                // be released before reserving the replacement's finite charge.
                entry->identity_charge.reset();
                failure = QStringLiteral("Directory identity memory budget exhausted");
                entry->identity_charge = reserve_plan(sizeof(Entry) + 128 +
                    4 * (sizeof(std::weak_ptr<Entry>) + 8 * sizeof(void*)) +
                    size_t(path.capacity() + 1) * sizeof(QChar) + 2 * directory_plan_key_bytes(physical_key) +
                    size_t(physical_key.components.size() + 1) * (sizeof(Route_node) + 8 * sizeof(void*)), failure);
                if (!entry->identity_charge) {
                    entry->budget_refused = true;
                    m_identity_budget_refused.insert(entry.get());
                    known = false;
                }
                else {
                    entry->budget_refused = false;
                    m_identity_budget_refused.erase(entry.get());
                    try {
                        insert_windows_route(physical_key, entry);
                    }
                    catch (const std::bad_alloc&) {
                        erase_windows_route(m_windows_routes, physical_key, entry.get());
                        entry->budget_refused = true;
                        m_identity_budget_refused.insert(entry.get());
                        known = false;
                    }
                }
            }
            const bool identity_changed = entry->identity_known != known ||
                (known && (!same_windows_directory_identity(identity, entry->identity) ||
                    entry->physical_key != physical_key));
            // Recursive native coverage invalidates descendant identities on
            // topology changes. Explicit paths still need boundary validation:
            // a junction above them can redirect outside the watched target.
            const auto protecting_anchor = known && !entry->anchor_input
                ? covering_windows_anchor(m_windows_desired, physical_key) : nullptr;
            const bool protected_identity = protecting_anchor && protecting_anchor->native_id != 0;
            schedule_identity(*entry, protected_identity ? Clock::time_point::max() : Clock::now() + k_retry_interval);
            if (protected_identity && entry->native_id == 0) {
                m_binding_entries.insert(entry->key, entry);
            }
            changed |= protected_identity && entry->native_id == 0;
            if (identity_changed || (!known && entry->failure != failure)) {
                changed = true;
                m_binding_entries.insert(entry->key, entry);
                if (identity_changed && entry->identity_known) {
                    for (const auto& descendant : m_entries) {
                        if (descendant != entry && path_name::is_ancestor_of_key(entry->path, descendant->key)) {
                            schedule_identity(*descendant);
                        }
                    }
                }
                if (entry->anchor_input) {
                    ++m_windows_plan_generation;
                }
                if (entry->identity_known && (!known || entry->physical_key != physical_key)) {
                    erase_windows_route(m_windows_routes, entry->physical_key, entry.get());
                }
                const bool first_identity = known && !entry->identity_known && entry->native_id == 0;
                lose(*entry, first_identity ? QString{} :
                    known ? QStringLiteral("Directory identity changed") : failure, lock,
                    first_identity ? Coverage_state::PENDING : Coverage_state::FAILED);
                entry->identity_known = known;
                entry->identity = identity;
                entry->physical_path = path;
                entry->physical_key = physical_key;
                entry->anchor.reset();
                if (!known) {
                    entry->identity_charge.reset();
                    entry->physical_path.clear();
                    entry->physical_key = {};
                }
            }
            if (known && !entry->anchor && entry->state != Coverage_state::FAILED) {
                entry->failure.clear();
            }
        }
        m_identity_round = {};
        return changed;
    }

    static std::shared_ptr<Entry> covering_windows_anchor(
        const QMap<path_name::Key, std::shared_ptr<Entry>>& anchors, path_name::Key key)
    {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::windows_ancestor_searches;
#endif
        for (;;) {
            if (const auto anchor = anchors.value(key)) {
                return anchor;
            }
            if (key.components.isEmpty()) {
                return {};
            }
            key.components.removeLast();
        }
    }

    void plan_windows_anchors()
    {
        if (!m_windows_collecting && !m_windows_choosing) {
            if (m_windows_applied_plan == m_windows_plan_generation &&
                (!m_windows_plan_budget_refused || Clock::now() < m_windows_plan_retry))
            {
                return;
            }
            m_windows_build_generation = m_windows_plan_generation;
            m_windows_root_cursor = 0;
            m_windows_candidates.clear();
            m_windows_build_desired.clear();
            m_windows_candidate_cursor = {};
            m_windows_collecting = true;
        }
        if (m_windows_collecting) {
            auto next = m_roots.upperBound(m_windows_root_cursor);
            int visited = 0;
            while (next != m_roots.end() && visited++ != k_native_operations_per_turn) {
                m_windows_root_cursor = next.key();
                const auto root = next.value().lock();
                ++next;
                if (!live(root) || !root->guard || !root->guard->identity_known) {
                    continue;
                }
                // Captured identity paths establish actual recursive reachability.
                // Explicit aliases retain their lexical replacement-parent reason.
                const auto& guard = *root->guard;
                m_windows_candidates.insert(guard.physical_key, {guard.physical_path, guard.identity_charge});
                if (root->content->identity_known) {
                    const auto parent = QFileInfo(root->content->physical_path).absolutePath();
                    auto parent_key = root->content->physical_key;
                    if (!parent_key.components.isEmpty()) {
                        parent_key.components.removeLast();
                    }
                    m_windows_candidates.insert(std::move(parent_key), {parent, root->content->identity_charge});
                }
            }
            if (next != m_roots.end()) {
                m_backend.wake();
                return;
            }
            m_windows_collecting = false;
            if (m_windows_build_generation != m_windows_plan_generation) {
                m_backend.wake();
                return;
            }
            m_windows_choosing = true;
            m_windows_plan_budget_refused = false;
            m_windows_plan_failure.clear();
        }
        auto next = m_windows_candidates.upperBound(m_windows_candidate_cursor);
        int visited = 0;
        while (next != m_windows_candidates.end() && visited++ != k_native_operations_per_turn) {
            const auto key = next.key();
            const auto path = next.value().path;
            m_windows_candidate_cursor = key;
            ++next;
            // Ancestors sort before descendants; prefix lookup avoids comparing
            // every independent root against every other root.
            if (covering_windows_anchor(m_windows_build_desired, key)) {
                continue;
            }
            auto anchor = m_windows_anchors.value(key);
            if (!anchor) {
                QString failure = QStringLiteral("Directory ancestor memory budget exhausted");
                auto charge = reserve_plan(sizeof(Entry) + 384 +
                    size_t(path.capacity() + 1) * sizeof(QChar) + 2 * directory_plan_key_bytes(key), failure);
                if (!charge) {
                    m_windows_plan_budget_refused = true;
                    m_windows_plan_failure = std::move(failure);
                    continue;
                }
                try {
                    anchor = std::make_shared<Entry>();
                    anchor->identity_charge = std::move(charge);
                    anchor->path = path;
                    anchor->key = key;
                    anchor->physical = true;
                    anchor->revision = s_next_coverage_revision.fetch_add(1);
                    m_windows_anchors.insert(key, anchor);
                }
                catch (const std::bad_alloc&) {
                    m_windows_plan_budget_refused = true;
                    m_windows_plan_failure = QStringLiteral("Directory observation plan allocation failed");
                    continue;
                }
            }
            try {
                m_windows_build_desired.insert(key, std::move(anchor));
            }
            catch (const std::bad_alloc&) {
                m_windows_plan_budget_refused = true;
                m_windows_plan_failure = QStringLiteral("Directory observation plan allocation failed");
            }
        }
        if (next != m_windows_candidates.end()) {
            m_backend.wake();
            return;
        }
        m_windows_choosing = false;
        if (m_windows_build_generation != m_windows_plan_generation) {
            m_windows_build_desired.clear();
            m_backend.wake();
            return;
        }
        m_windows_applied_plan = m_windows_build_generation;
        m_windows_desired = std::move(m_windows_build_desired);
        m_windows_candidates.clear();
        for (const auto& anchor : m_windows_anchors) {
            anchor->desired = m_windows_desired.contains(anchor->key);
            schedule_native(*anchor, anchor->desired
                ? (anchor->native_id ? anchor->validate_at : anchor->retry_at)
                : Clock::time_point::max());
        }
        m_windows_plan_retry = Clock::now() + k_retry_interval;
    }

    bool arm_windows_entries(std::unique_lock<std::mutex>& lock, bool bindings_pending)
    {
        bool changed = validate_windows_directories(lock);
        const auto applied_plan = m_windows_applied_plan;
        const auto previous_desired = m_windows_desired;
        const auto plan_failure = m_windows_plan_failure;
        plan_windows_anchors();
        bool shared_changed = previous_desired != m_windows_desired || plan_failure != m_windows_plan_failure;
        changed |= shared_changed || applied_plan != m_windows_applied_plan;
        auto& desired = m_windows_desired;

        size_t required_count = m_backend.allocated_registrations();
        size_t required_bytes = m_backend.allocated_bytes();
        bool overflow = false;
        for (const auto& anchor : desired) {
            if (anchor->native_id == 0) {
                overflow |= !add_usage(required_count, 1);
                overflow |= !add_usage(required_bytes, Direct_native_backend::registration_bytes(anchor->path));
            }
        }
        const bool constrained = overflow || m_windows_plan_budget_refused || (m_limits.bounded_workload &&
            (required_count > m_limits.registrations || required_bytes > m_limits.bytes));
        if (constrained && (bindings_pending || changed)) {
            for (const auto& logical : m_entries) {
                if (logical->anchor && !desired.contains(logical->anchor->key)) {
                    schedule_identity(*logical);
                    lose(*logical, QStringLiteral("Ancestor coverage replacement is pending"), lock);
                    logical->anchor.reset();
                    changed = true;
                }
            }
            changed |= retire_windows_anchors(lock);
        }
        const bool native_changed = arm_native_entries(desired, lock);
        shared_changed |= native_changed;
        changed |= native_changed;
        if (shared_changed) {
            for (const auto& entry : m_entries) {
                m_binding_entries.insert(entry->key, entry);
            }
        }
        const auto pending = std::exchange(m_binding_entries, {});
        for (const auto& weak : pending) {
            const auto logical = weak.lock();
            if (!logical) {
                continue;
            }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            count_entry_maintenance(*logical, &Maintenance_counts::binding_candidates);
            if (logical->unavailable) {
                const auto failure = QStringLiteral("Injected native directory unavailability");
                if (logical->native_id != 0 || logical->failure != failure) {
                    lose(*logical, failure, lock);
                    changed = true;
                }
                continue;
            }
#endif
            std::shared_ptr<Entry> anchor;
            if (logical->identity_known) {
                // Identity changes clear the binding, and a new plan marks
                // obsolete anchors undesired. Otherwise the ancestor is stable.
                anchor = logical->anchor && logical->anchor->desired ? logical->anchor :
                    covering_windows_anchor(desired, logical->physical_key);
            }
            if (!anchor || anchor->native_id == 0) {
                // Preserve an existing reason while its replacement can coexist.
                if (!constrained && logical->identity_known && logical->anchor &&
                    logical->anchor->native_id != 0)
                {
                    continue;
                }
                const bool failed = constrained || logical->state == Coverage_state::FAILED ||
                    (anchor && anchor->state == Coverage_state::FAILED);
                const auto failure = anchor && !anchor->failure.isEmpty() ? anchor->failure :
                    !logical->failure.isEmpty() ? logical->failure :
                    !m_windows_plan_failure.isEmpty() ? m_windows_plan_failure :
                    failed ? QStringLiteral("Ancestor coverage admission is unavailable") : QString{};
                const auto state = failed ? Coverage_state::FAILED : Coverage_state::PENDING;
                if (logical->native_id != 0 || logical->failure != failure || logical->state != state) {
                    lose(*logical, failure, lock, state);
                    changed = true;
                }
                logical->anchor = std::move(anchor);
                continue;
            }
            if (logical->anchor != anchor || logical->anchor_revision != anchor->revision ||
                logical->native_id == 0)
            {
                // A snapshot taken before native capture began has an
                // unobserved interval. Recheck it under the armed ancestor
                // before admitting scans or declaring the binding covered.
                if (!logical->anchor_input && logical->validate_at != Clock::time_point::max()) {
                    schedule_identity(*logical);
                    m_backend.wake();
                    changed = true;
                    continue;
                }
                logical->anchor = anchor;
                logical->anchor_revision = anchor->revision;
                const bool failures_changed = logical->state == Coverage_state::FAILED;
                set_native_id(*logical, anchor->native_id);
                logical->state = Coverage_state::COVERED;
                logical->failure.clear();
                logical->revision = s_next_coverage_revision.fetch_add(1);
                mark_entry(*logical, failures_changed);
                changed = true;
            }
        }
        changed |= retire_windows_anchors(lock);
        return changed;
    }
#endif

    bool arm_entries(std::unique_lock<std::mutex>& lock, bool bindings_pending)
    {
#ifdef Q_OS_WIN
        return arm_windows_entries(lock, bindings_pending);
#else
        Q_UNUSED(bindings_pending);
        return arm_native_entries(m_entries, lock);
#endif
    }

    bool entry_identity_matches(const Entry& entry, QString& error, bool* missing = nullptr) const
    {
        if (missing) {
            *missing = false;
        }
#ifdef Q_OS_WIN
        if (!entry.identity_known) {
            error = entry.failure.isEmpty() ? QStringLiteral("Directory identity is unavailable") : entry.failure;
            return false;
        }
        windows_directory_identity_t identity{};
        QString physical_path;
        return capture_windows_directory_identity(
            entry.path, identity, physical_path, error, missing) &&
            same_windows_directory_identity(identity, entry.identity) &&
            path_name::matches_key(physical_path, entry.physical_key);
#else
        Q_UNUSED(error);
        return m_backend.identity_matches(entry.native_id);
#endif
    }

    bool arm_native_entries(QMap<path_name::Key, std::shared_ptr<Entry>>& entries,
        std::unique_lock<std::mutex>& lock)
    {
        if (entries.isEmpty()) {
            m_arm_round = {};
            return false;
        }
        bool changed = false;
        if (m_arm_round == Clock::time_point{}) {
            m_arm_round = Clock::now();
        }
        int operations = 0;
        while (!m_native_due.empty() && m_native_due.begin()->first.first <= m_arm_round) {
            if (operations == k_native_operations_per_turn) {
                m_backend.wake();
                return changed;
            }
            const auto entry = m_native_due.begin()->second.lock();
            m_native_due.erase(m_native_due.begin());
            if (!entry || entries.value(entry->key) != entry) {
                continue;
            }
            ++operations;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            if (entry->unavailable && entry->native_id != 0) {
                lose(*entry, QStringLiteral("Injected native directory unavailability"), lock);
                changed = true;
            }
#endif
            if (entry->native_id != 0) {
                if (Clock::now() < entry->validate_at) {
                    schedule_native(*entry, entry->validate_at);
                    continue;
                }
                unlock(lock);
                const bool valid = m_backend.identity_matches(entry->native_id);
                lock.lock();
                entry->validate_at = Clock::now() + k_retry_interval;
                schedule_native(*entry, entry->validate_at);
                if (!valid) {
                    lose(*entry, QStringLiteral("Directory identity changed"), lock);
                    changed = true;
                }
                continue;
            }
            if (Clock::now() < entry->retry_at) {
                schedule_native(*entry, entry->retry_at);
                continue;
            }
            entry->retry_at = Clock::now() + k_retry_interval;
            schedule_native(*entry, entry->retry_at);
            QString failure;
            const auto native_id = ++m_next_native;
            const size_t bytes = Direct_native_backend::registration_bytes(entry->path);
            bool armed = false;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            if (entry->unavailable) {
                failure = QStringLiteral("Injected native directory unavailability");
            }
            else
#endif
            if (m_backend.allocated_registrations() == std::numeric_limits<size_t>::max() ||
                bytes > std::numeric_limits<size_t>::max() - m_backend.allocated_bytes())
            {
                failure = QStringLiteral("Native directory accounting overflow");
            }
            else
            if (m_limits.bounded_workload && m_backend.allocated_registrations() >= m_limits.registrations) {
                failure = QStringLiteral("Native directory registration budget exhausted");
            }
            else
            if (m_limits.bounded_workload &&
                (bytes > m_limits.bytes || m_backend.allocated_bytes() > m_limits.bytes - bytes))
            {
                failure = QStringLiteral("Native directory memory budget exhausted");
            }
            else {
                unlock(lock);
                armed = m_backend.arm(native_id, entry->path, failure);
                lock.lock();
            }
            if (armed) {
                const bool failures_changed = entry->state == Coverage_state::FAILED;
                set_native_id(*entry, native_id);
                entry->state = Coverage_state::COVERED;
                entry->failure.clear();
                entry->revision = s_next_coverage_revision.fetch_add(1);
                entry->validate_at = Clock::now() + k_retry_interval;
                schedule_native(*entry, entry->validate_at);
                m_native_entries.insert(native_id, entry);
                mark_entry(*entry, failures_changed);
                changed = true;
            }
            else {
                changed |= entry->state != Coverage_state::FAILED;
                entry->state = Coverage_state::FAILED;
                if (entry->failure != failure) {
                    entry->failure = failure;
                    entry->revision = s_next_coverage_revision.fetch_add(1);
                    mark_entry(*entry);
                    changed = true;
                }
            }
        }
        m_arm_round = {};
        return changed;
    }

    void notify_root(const std::shared_ptr<Root>& root, const Native_batch& batch,
        QList<Notification>& notifications)
    {
        const auto owner = root->owner.lock();
        if (owner && owner->active && owner->roots.contains(root)) {
            notifications.append({owner, batch});
        }
    }

    Coverage_status coverage_status(const Root& root) const
    {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (root.forced_failure) {
            return {Coverage_state::FAILED, QStringLiteral("Injected directory coverage loss")};
        }
#endif
        if (!root.expansion_failure.isEmpty()) {
            return {Coverage_state::FAILED, root.expansion_failure};
        }
        for (const auto& entry : {root.content, root.guard}) {
            if (entry && entry->state == Coverage_state::FAILED) {
                return {Coverage_state::FAILED, entry->failure.isEmpty()
                    ? QStringLiteral("Native directory coverage failed") : entry->failure};
            }
        }
        for (const auto& node : root.nodes) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            if (const auto owner = root.owner.lock()) {
                ++owner->maintenance.read_summary_nodes;
            }
#endif
            if (!node->error.isEmpty()) {
                return {Coverage_state::FAILED, node->error};
            }
            if (node->entry->state == Coverage_state::FAILED) {
                return {Coverage_state::FAILED, node->entry->failure.isEmpty()
                    ? QStringLiteral("Native directory coverage failed") : node->entry->failure};
            }
        }
        return {root.covered && root.expansion_complete && root.content->native_id != 0 &&
            root.guard && root.guard->native_id != 0
            ? Coverage_state::COVERED : Coverage_state::PENDING, {}};
    }

    Native_batch reconciliation(const Root& root) const
    {
        Native_batch batch;
        batch.root = batch.scope = root.path;
        batch.coverage_revision = root.revision;
        batch.rescan_required = true;
        const auto& status = root.read_status;
        batch.reason = status.state == Coverage_state::FAILED
            ? Native_reason::REGISTRATION_FAILED : Native_reason::COVERAGE_CHANGED;
        batch.diagnostic = status.state == Coverage_state::FAILED ? status.diagnostic : root.covered
            ? QStringLiteral("Native directory coverage armed; reconciliation required")
            : QStringLiteral("Directory observation coverage is pending");
        const bool pending = std::any_of(root.nodes.cbegin(), root.nodes.cend(),
            [](const auto& node) { return node->filter_pending; });
        if (pending && status.state == Coverage_state::PENDING) {
            batch.reason = Native_reason::DIRECTORY_FILTER_PENDING;
            batch.diagnostic = QStringLiteral("Directory eligibility is pending");
        }
        batch.consumer_reconciliation_only =
            root.cause == Reconciliation_cause::CONSUMER_RECONCILIATION;
        batch.initial_admission_only = root.cause == Reconciliation_cause::INITIAL_ADMISSION;
        return batch;
    }

    void reconcile(QList<Notification>& notifications, bool arming_complete)
    {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (m_maintenance_observer) {
            m_maintenance_observer(Maintenance_stage::RECONCILE);
        }
#endif
        const auto pending_roots = std::exchange(m_reconcile_roots, {});
        for (const auto& weak : pending_roots) {
            const auto root = weak.lock();
            if (!live(root)) {
                continue;
            }
            refresh_root_resources(root);
            const auto read = qScopeGuard([&] { mark_read(root); });
            const bool failed = root->read_status.state == Coverage_state::FAILED;
            const bool pending = std::any_of(root->nodes.cbegin(), root->nodes.cend(),
                [](const auto& node) { return node->filter_pending; });
            if (failed) {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
            }
            const bool unresolved = failed || pending;
            bool expanded = root->content->native_id != 0 && root->guard &&
                root->guard->native_id != 0 && root->expansion_complete && !unresolved;
#ifdef Q_OS_WIN
            // A superseded descendant handle still blocks moves until its
            // cancellation completes, even after the replacement anchor arms.
            const auto blocks_move = [&](const auto& anchor) {
                return path_name::is_within_key(anchor->path, root->content->physical_key);
            };
            const bool handles_released = std::none_of(m_windows_anchors.cbegin(), m_windows_anchors.cend(),
                [&](const auto& anchor) {
                    return anchor->native_id != 0 && !anchor->desired && blocks_move(anchor);
                });
            const bool retirements_complete = std::none_of(m_windows_retiring.cbegin(), m_windows_retiring.cend(), blocks_move);
            if (handles_released && retirements_complete) {
                m_retirement_blocked_roots.remove(root->id);
            }
            else {
                m_retirement_blocked_roots.insert(root->id, root);
            }
            expanded &= handles_released && retirements_complete;
#endif
            root->initial_attempted |= expanded || unresolved;
            // Initial admission is asynchronous for Service, but its first
            // reconciliation describes a completed attempt, not queued scans.
            // Recovering an already-incomplete plan retains its obligation;
            // partial scan progress does not create another acquisition epoch.
            if ((root->revision == 0 && !root->initial_attempted) ||
                (root->revision != 0 && !root->covered && !expanded && !unresolved))
            {
                continue;
            }
            const auto guard_revision = root->guard ? root->guard->revision : 0;
            auto native_revision = std::max(root->content->revision, guard_revision);
            for (const auto& node : root->nodes) {
                native_revision = std::max(native_revision, node->entry->revision);
            }
            // A retained descendant can lose coverage before the replacement
            // plan rediscovers it. Publish that known loss even when the new
            // plan's own native entries and pending diagnostic are unchanged.
            const bool unpublished_loss = root->read_revision > root->revision;
            if (!unpublished_loss && root->revision != 0 && !root->covered && !expanded && unresolved &&
                native_revision == root->published_native_revision &&
                reconciliation(*root).diagnostic == root->published_failure)
            {
                // Retrying the same failed expansion does not invalidate an
                // acquisition already reconciling that incomplete generation.
                // Descendant native revisions still expose a genuinely new loss.
                if (arming_complete) {
                    root->refresh = false;
                }
                continue;
            }
            bool reported_coverage = expanded;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            reported_coverage &= !root->forced_failure;
#endif
            if (!unpublished_loss && root->revision != 0 && root->content_revision == root->content->revision &&
                root->guard_revision == guard_revision &&
                native_revision <= root->published_native_revision && !unresolved &&
                root->covered == reported_coverage)
            {
                if (arming_complete) {
                    root->refresh = false;
                }
                continue;
            }
            root->content_revision = root->content->revision;
            root->guard_revision = guard_revision;
            root->revision = s_next_coverage_revision.fetch_add(1);
            root->covered = reported_coverage;
            mark_read(root);
            if (arming_complete) {
                root->refresh = false;
            }
            auto batch = reconciliation(*root);
            root->published_native_revision = native_revision;
            root->published_failure = root->covered ? QString{} : batch.diagnostic;
            notify_root(root, batch, notifications);
        }
        for (const auto id : m_attempt_clients) {
            const auto client = m_clients.value(id);
            if (!client) {
                continue;
            }
            if (client->initial && arming_complete) {
                for (const auto& root : client->roots) {
                    if (root->revision == 0) {
                        continue;
                    }
                    const bool included = std::any_of(notifications.cbegin(), notifications.cend(),
                        [&](const Notification& item) {
                            return item.client == client && item.batch.root == root->path;
                        });
                    if (!included) {
                        notifications.append({client, reconciliation(*root)});
                    }
                }
                client->initial = false;
            }
            if (arming_complete) {
                client->applied = client->prepared;
            }
        }
        refresh_resource_usage();
        m_changed.notify_all();
    }

    void refresh_resource_usage()
    {
        m_resources.logical_directories = int(m_entries.size());
        m_resources.native_threads = 2;
#ifdef Q_OS_WIN
        m_resources.desired = int(m_windows_anchors.size());
        m_resources.armed = int(std::count_if(m_windows_anchors.cbegin(), m_windows_anchors.cend(),
            [](const auto& entry) { return entry->native_id != 0; }));
#else
        m_resources.desired = int(m_entries.size());
        m_resources.armed = m_resources.covered_logical_directories;
#endif
        m_resources.failed = m_resources.desired - m_resources.armed;
        m_resources.retiring = std::max(0, int(m_backend.allocated_registrations()) - m_resources.armed);
        m_resources.native_bytes = m_backend.allocated_bytes();
        m_resources.plan_bytes = plan_bytes();
        m_resources.scan_result_bytes = m_scan_result_bytes;
        const auto scans = m_scanner->resource_counts();
        m_resources.scan_jobs = scans.first;
        m_resources.scan_threads = scans.second;
        const auto drain = m_backend.resource_counts();
        m_resources.handoff_detail_bytes = drain.detail_bytes;
        m_resources.peak_handoff_detail_bytes = drain.peak_detail_bytes;
        m_resources.native_batches = drain.batches;
        m_resources.kernel_overflows = drain.kernel_overflows;
        m_resources.decoder_budget_losses = drain.decoder_budget_losses;
        m_resources.handoff_overflows = drain.handoff_overflows;
    }

    struct Logical_change
    {
        std::shared_ptr<Entry> entry;
        Native_batch batch;
        bool coverage_lost = false;
    };
    using Logical_changes = std::map<Entry*, Logical_change>;

#ifdef Q_OS_WIN
    static Event windows_logical_event(Event event, const Entry& logical)
    {
        const auto lexical = [&](const QString& path) {
            if (!path_name::is_within_key(path, logical.physical_key)) {
                return path;
            }
            return logical.path + path.mid(logical.physical_path.size());
        };
        event.path = lexical(event.path);
        event.old_path = lexical(event.old_path);
        return event;
    }

    Logical_changes windows_logical_changes(const Direct_change& change, const std::shared_ptr<Entry>& anchor)
    {
        Logical_changes result;
        const auto include = [&](const std::shared_ptr<Entry>& logical) -> Native_batch& {
            const auto [position, inserted] = result.try_emplace(logical.get());
            auto& item = position->second;
            if (inserted) {
                item.entry = logical;
                item.batch = change.batch;
                item.batch.events.clear();
                item.batch.root = item.batch.scope = logical->path;
            }
            return item.batch;
        };
        for (const auto& event : change.batch.events) {
            const auto route = [&](const std::shared_ptr<Entry>& logical) {
                if (logical->anchor != anchor) {
                    return;
                }
                auto& batch = include(logical);
                const auto detail = windows_logical_event(event, *logical);
                if (!batch.events.contains(detail)) {
                    batch.events.append(detail);
                }
            };
            for (const auto& path : {event.path, event.old_path}) {
                if (path.isEmpty()) {
                    continue;
                }
                find_windows_routes(QFileInfo(path).absolutePath(), false, route);
                if (event.kind != Event_kind::MODIFIED) {
                    find_windows_routes(path, false, route);
                }
                if (event.entry_type != Entry_type::NON_DIRECTORY) {
                    find_windows_routes(path, event.kind != Event_kind::MODIFIED,
                        [&](const std::shared_ptr<Entry>& logical) {
                            if (logical->anchor == anchor) {
                                schedule_identity(*logical);
                            }
                        });
                }
            }
        }
        if (change.batch.rescan_required && !change.batch.rescan_event_paths_complete) {
            // Genuine lost detail still visits the complete affected anchor.
            for (const auto& logical : m_entries) {
                if (logical->anchor == anchor) {
                    schedule_identity(*logical);
                    include(logical);
                }
            }
        }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        native_test_hooks::windows_logical_routes += result.size();
#endif
        return result;
    }
#endif

    bool ingest_logical_changes(const Logical_changes& changes, QList<Notification>& notifications,
        std::unique_lock<std::mutex>& lock)
    {
        bool work = false;
        for (const auto& [pointer, change] : changes) {
            Q_UNUSED(pointer);
            const auto& entry = change.entry;
            if (change.coverage_lost) {
                lose(*entry, change.batch.diagnostic, lock);
                work = true;
            }
            else
            if (change.batch.rescan_required && !change.batch.rescan_event_paths_complete) {
#ifdef Q_OS_WIN
                // Confirmed overflow retains the native identity. Keep current
                // scan results, then request_scan requires another enumeration
                // before completion if a scan is already in flight.
                if (change.batch.reason != Native_reason::QUEUE_OVERFLOW)
#endif
                {
                    entry->revision = s_next_coverage_revision.fetch_add(1);
                    mark_entry(*entry);
                    work = true;
                }
            }
        }
        QMap<uint64_t, std::shared_ptr<Root>> affected;
        for (const auto& [entry, change] : changes) {
            Q_UNUSED(change);
            for (const auto& root : interested_roots(*entry)) {
                affected.insert(root->id, root);
            }
        }
        for (const auto& root : affected) {
            if (!live(root)) {
                continue;
            }
            bool publish = false;
            Native_batch outgoing;
            const auto append = [&](Native_batch batch) {
                if (!publish) {
                    outgoing = std::move(batch);
                    publish = true;
                }
                else {
                    outgoing.rescan_event_paths_complete =
                        (!outgoing.rescan_required || outgoing.rescan_event_paths_complete) &&
                        (!batch.rescan_required || batch.rescan_event_paths_complete);
                    outgoing.rescan_required |= batch.rescan_required;
                    for (const auto& event : batch.events) {
                        if (!outgoing.events.contains(event)) {
                            outgoing.events.append(event);
                        }
                    }
                }
            };
            const auto content = [&](const Logical_change& change, const std::shared_ptr<Root::Node>& node) {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                auto batch = change.batch;
                if (node) {
                    const bool topology = batch.rescan_required ||
                        std::any_of(batch.events.cbegin(), batch.events.cend(), [&](const Event& event) {
                            return (event.kind != Event_kind::MODIFIED &&
                                    event.entry_type != Entry_type::NON_DIRECTORY) ||
                                (root->mode == Watch_mode::DISCOVERY_RECURSIVE &&
                                    (QFileInfo(event.path).fileName() == QStringLiteral(".git") ||
                                        QFileInfo(event.old_path).fileName() == QStringLiteral(".git")));
                        });
                    if (topology && !batch.rescan_required) {
                        batch.rescan_event_paths_complete = true;
                    }
                    batch.rescan_required |= topology;
                    if (topology) {
                        request_scan(root, node, batch.rescan_event_paths_complete);
                        work = true;
                    }
                }
                append(std::move(batch));
            };
            // Sparse detail looks up just its directories. Broad loss walks the
            // root's actual nodes once, without multiplying all roots by entries.
            if (root->nodes.size() <= qsizetype(changes.size())) {
                for (const auto& node : root->nodes) {
                    const auto found = changes.find(node->entry.get());
                    if (found != changes.end()) {
                        content(found->second, node);
                    }
                }
            }
            else {
                for (const auto& [entry, change] : changes) {
                    const auto node = root->nodes.value(entry->key);
                    if (node) {
                        content(change, node);
                    }
                }
            }
            if (!root->nodes.contains(root->content->key)) {
                const auto found = changes.find(root->content.get());
                if (found != changes.end()) {
                    content(found->second, {});
                }
            }
            // Retained descendants protect a replacing eligibility plan even
            // before the new plan rediscovers their nodes.
            if (std::any_of(changes.cbegin(), changes.cend(), [&](const auto& item) {
                    return path_name::is_within_key(item.second.entry->path, root->key);
                }))
            {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
            }
            const auto guard_change = changes.find(root->guard.get());
            if (root->guard != root->content && guard_change != changes.end()) {
                const auto& change = guard_change->second;
                const bool registration_wide =
                    change.batch.rescan_required && !change.batch.rescan_event_paths_complete;
                const bool relevant = registration_wide ||
                    std::any_of(change.batch.events.cbegin(), change.batch.events.cend(),
                        [&](const Event& event) {
                            return path_name::is_ancestor_of_key(event.path, root->key) ||
                                path_name::is_ancestor_of_key(event.old_path, root->key);
                        });
                if (relevant) {
                    root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                    auto guard = change.batch;
                    guard.events.removeIf([&](const Event& event) {
                        return event.kind == Event_kind::MODIFIED ||
                            (!path_name::is_ancestor_of_key(event.path, root->key) &&
                                !path_name::is_ancestor_of_key(event.old_path, root->key));
                    });
                    if (registration_wide || !guard.events.isEmpty()) {
                        append(std::move(guard));
                        mark_root(root);
                        schedule_parent(root, {});
                        work = true;
                    }
                    // A parent can report a directory timestamp/attribute change
                    // after a child edit. The content registration still covers
                    // that edit; validate its identity without publishing a
                    // content event or borrowing an unrelated rename's rescan.
#ifdef Q_OS_WIN
                    schedule_identity(*root->content);
#else
                    root->content->validate_at = {};
                    schedule_native(*root->content, {});
#endif
                    root->content->retry_at = {};
                }
            }
            if (publish) {
                outgoing.root = outgoing.scope = root->path;
                outgoing.coverage_revision = root->revision;
                notify_root(root, outgoing, notifications);
            }
        }
        return work;
    }

    bool ingest(const QList<Direct_change>& changes, QList<Notification>& notifications,
        std::unique_lock<std::mutex>& lock)
    {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        if (m_maintenance_observer) {
            m_maintenance_observer(Maintenance_stage::INGEST);
        }
#endif
        bool work = false;
        for (const auto& change : changes) {
            const auto entry = m_native_entries.value(change.registration).lock();
            if (!entry || entry->native_id != change.registration) {
                continue;
            }
#ifdef Q_OS_WIN
            if (change.coverage_lost) {
                lose(*entry, change.batch.diagnostic, lock);
                work = true;
            }
            work |= ingest_logical_changes(windows_logical_changes(change, entry), notifications, lock);
#else
            work |= ingest_logical_changes({{entry.get(), {entry, change.batch, change.coverage_lost}}},
                notifications, lock);
#endif
        }
        return work;
    }

    void deliver(QList<Notification>& notifications, std::unique_lock<std::mutex>& lock)
    {
        for (auto& notification : notifications) {
            const auto client = notification.client;
            if (!client->active) {
                continue;
            }
            ++client->callbacks;
            unlock(lock);
            client->callback(notification.batch);
            lock.lock();
            --client->callbacks;
            m_changed.notify_all();
        }
    }

    void finish_attempts()
    {
        const auto pending = m_attempt_clients;
        for (const auto id : pending) {
            const auto client = m_clients.value(id);
            if (!client) {
                m_attempt_clients.erase(id);
                continue;
            }
            if (std::all_of(client->roots.cbegin(), client->roots.cend(),
                [](const auto& root) { return root->initial_attempted; }))
            {
                client->delivered = client->applied;
                if (client->delivered >= client->requested) {
                    m_attempt_clients.erase(id);
                }
            }
        }
        m_changed.notify_all();
    }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    void apply_test_requests(std::unique_lock<std::mutex>& lock, QList<Notification>& notifications)
    {
        // Native retirement releases the lock. A completed test may detach its
        // client then, so keep the request traversal independent of that map.
        const auto clients = m_clients.values();
        for (const auto& client : clients) {
            if (!client->active || (!client->invalidate_content && !client->inject_overflow)) {
                continue;
            }
            const bool invalidate = std::exchange(client->invalidate_content, false);
            const bool overflow = std::exchange(client->inject_overflow, false);
            QMap<uint64_t, std::shared_ptr<Entry>> entries;
            for (const auto& root : client->roots) {
#ifdef Q_OS_WIN
                if (root->content->anchor) {
                    entries.insert(root->content->anchor->native_id, root->content->anchor);
                }
                if (root->guard && root->guard->anchor) {
                    entries.insert(root->guard->anchor->native_id, root->guard->anchor);
                }
#else
                entries.insert(root->content->native_id, root->content);
                for (const auto& node : root->nodes) {
                    entries.insert(node->entry->native_id, node->entry);
                }
#endif
            }
            entries.remove(0);
            for (const auto& entry : entries) {
                if (invalidate) {
                    lose(*entry, QStringLiteral("Injected native registration loss"), lock);
                }
                if (overflow) {
                    Native_batch batch;
                    batch.root = batch.scope = entry->path;
                    batch.rescan_required = true;
                    batch.reason = Native_reason::QUEUE_OVERFLOW;
                    ingest({Direct_change{entry->native_id, batch, false}}, notifications, lock);
                }
            }
        }
    }
#endif

    std::chrono::milliseconds next_wait_timeout()
    {
        if (m_work_pending || !m_scan_results.isEmpty() || !m_dirty_roots.isEmpty() || !m_dirty_clients.empty()) {
            return std::chrono::milliseconds(0);
        }
        auto deadline = Clock::time_point::max();
        const auto include_due = [&deadline](auto& queue) {
            while (!queue.empty() && queue.begin()->second.expired()) {
                queue.erase(queue.begin());
            }
            if (!queue.empty()) {
                deadline = std::min(deadline, queue.begin()->first.first);
            }
        };
        include_due(m_parent_due);
        include_due(m_scan_due);
        include_due(m_native_due);
#ifdef Q_OS_WIN
        if (m_windows_collecting || m_windows_choosing ||
            m_windows_applied_plan != m_windows_plan_generation || !m_binding_entries.isEmpty())
        {
            return std::chrono::milliseconds(0);
        }
        include_due(m_identity_due);
        if (m_windows_plan_budget_refused) {
            deadline = std::min(deadline, m_windows_plan_retry);
        }
#endif
        if (deadline == Clock::time_point::max()) {
            return std::chrono::milliseconds::max();
        }
        return std::max(std::chrono::milliseconds(0),
            std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()));
    }

    void run()
    {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        ++native_test_hooks::direct_registry_threads;
#endif
        std::unique_lock lock(m_mutex);
        while (!m_stopped) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            ++native_test_hooks::registry_maintenance_turns;
#endif
            const auto due = Clock::now();
            while (!m_scan_due.empty() && m_scan_due.begin()->first.first <= due) {
                const auto root = m_scan_due.begin()->second.lock();
                m_scan_due.erase(m_scan_due.begin());
                if (live(root)) {
                    mark_root(root);
                }
            }
            bool work = std::exchange(m_work_pending, false);
            work |= !m_scan_results.isEmpty() || !m_dirty_roots.isEmpty() || !m_dirty_clients.empty();
            QList<Notification> notifications;
            if (work) {
                update_clients();
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
                apply_test_requests(lock, notifications);
#endif
                apply_scans(lock);
                release_replaced_roots();
                retire_entries(lock);
            }
            bool maintenance_changed = update_parents(lock);
            maintenance_changed |= arm_entries(lock, work || maintenance_changed);
            m_work_pending |= maintenance_changed;
            work |= maintenance_changed;
            if (work) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
                ++native_test_hooks::reconciliation_turns;
#endif
                start_scans();
                reconcile(notifications, true);
            }
            else {
                refresh_resource_usage();
            }
            deliver(notifications, lock);
            if (work) {
                finish_attempts();
            }
            const auto timeout = next_wait_timeout();
            unlock(lock);
            const auto incoming = m_backend.wait(timeout);
            lock.lock();
            m_work_pending |= incoming.capacity_changed;
            notifications.clear();
            const bool changed = ingest(incoming.changes, notifications, lock);
            if (changed) {
                m_work_pending = true;
                reconcile(notifications, false);
            }
            else {
                refresh_resource_usage();
            }
            deliver(notifications, lock);
            if (changed) {
                finish_attempts();
            }
        }
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
        --native_test_hooks::direct_registry_threads;
#endif
    }

    direct_limits_t m_limits;
    Direct_native_drain m_backend;
    mutable std::mutex m_mutex;
    // Readers retain only immutable interest/coverage values. This lock never
    // protects the registry graph, filesystem work or callbacks.
    mutable std::mutex m_read_mutex;
    QMap<uint64_t, std::shared_ptr<const Read_view>> m_read_views;
    std::set<uint64_t> m_read_dirty_clients;
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    std::function<void(Maintenance_stage)> m_maintenance_observer;
#endif
    std::condition_variable m_changed;
    QMap<uint64_t, std::shared_ptr<Client>> m_clients;
    std::shared_ptr<Plan_budget> m_plan_budget = std::make_shared<Plan_budget>();
    Clock::time_point m_arm_round{};
    bool m_work_pending = true;
    std::set<uint64_t> m_dirty_clients;
    std::set<uint64_t> m_attempt_clients;
    std::set<uint64_t> m_retiring_clients;
    QMap<uint64_t, std::weak_ptr<Root>> m_dirty_roots;
    QMap<uint64_t, std::weak_ptr<Root>> m_reconcile_roots;
    QMap<path_name::Key, std::weak_ptr<Entry>> m_retirement_candidates;
    std::map<std::pair<Clock::time_point, uint64_t>, std::weak_ptr<Root>> m_parent_due;
    std::map<std::pair<Clock::time_point, uint64_t>, std::weak_ptr<Root>> m_scan_due;
    std::map<std::pair<Clock::time_point, Entry*>, std::weak_ptr<Entry>> m_native_due;
    QMap<uint64_t, std::weak_ptr<Root>> m_roots;
    uint64_t m_scan_cursor = 0;
    QMap<path_name::Key, std::shared_ptr<Entry>> m_entries;
#ifdef Q_OS_WIN
    std::map<std::pair<Clock::time_point, Entry*>, std::weak_ptr<Entry>> m_identity_due;
    QMap<path_name::Key, std::weak_ptr<Entry>> m_binding_entries;
    std::set<Entry*> m_identity_budget_refused;
    QMap<uint64_t, std::weak_ptr<Root>> m_retirement_blocked_roots;
    QMap<path_name::Key, std::shared_ptr<Entry>> m_windows_anchors;
    Route_node m_windows_routes;
    QMap<uint64_t, std::shared_ptr<Entry>> m_windows_retiring;
    QMap<path_name::Key, std::shared_ptr<Entry>> m_windows_desired;
    QMap<path_name::Key, Anchor_candidate> m_windows_candidates;
    QMap<path_name::Key, std::shared_ptr<Entry>> m_windows_build_desired;
    uint64_t m_windows_plan_generation = 1;
    uint64_t m_windows_applied_plan = 0;
    uint64_t m_windows_build_generation = 0;
    uint64_t m_windows_root_cursor = 0;
    path_name::Key m_windows_candidate_cursor;
    bool m_windows_collecting = false;
    bool m_windows_choosing = false;
    bool m_windows_plan_budget_refused = false;
    QString m_windows_plan_failure;
    Clock::time_point m_windows_plan_retry{};
    Clock::time_point m_identity_round{};
#endif
    QMap<uint64_t, std::weak_ptr<Entry>> m_native_entries;
    Resource_counts m_resources;
    uint64_t m_next_client = 0;
    uint64_t m_next_native = 0;
    uint64_t m_next_root = 0;
    uint64_t m_next_scan = 0;
    QMap<uint64_t, Scan> m_scans;
    QList<Directory_scan_result> m_scan_results;
    size_t m_scan_result_bytes = 0;
    std::unique_ptr<Directory_scanner> m_scanner;
    bool m_stopped = false;
    std::thread m_worker;
};

Direct_registry::Direct_registry(direct_limits_t limits)
:
    m_impl(std::make_shared<Impl>(limits))
{
    const std::weak_ptr<Impl> weak = m_impl;
    m_impl->m_scanner = std::make_unique<Directory_scanner>(limits.scan_workers,
        [weak](Directory_scan_result result) {
            if (const auto state = weak.lock()) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
                std::function<void(Native_watcher::Expansion_stage)> observer;
                {
                    const std::lock_guard lock(state->m_mutex);
                    const auto root = state->m_scans.value(result.id).root.lock();
                    if (state->live(root)) {
                        observer = root->owner.lock()->expansion_observer;
                    }
                }
                if (observer) {
                    observer(Native_watcher::Expansion_stage::BEFORE_RESULT);
                }
#endif
                std::unique_lock lock(state->m_mutex);
                state->m_changed.wait(lock, [&] {
                    // A single supported directory may own more policy text than
                    // the queue allowance; it must still be able to make progress.
                    return state->m_stopped || state->m_scan_results.isEmpty() ||
                        (state->m_scan_results.size() < 64 && result.bytes <= k_directory_scan_result_bytes &&
                            state->m_scan_result_bytes <= k_directory_scan_result_bytes - result.bytes);
                });
                if (!state->m_stopped) {
                    const auto id = result.id;
                    const auto bytes = result.bytes;
                    try {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
                        if (native_test_hooks::scan_result_allocation_failure.load()) {
                            throw std::bad_alloc();
                        }
#endif
                        state->m_scan_results.append(std::move(result));
                        state->m_scan_result_bytes += bytes;
                    }
                    catch (const std::bad_alloc&) {
                        const auto request = state->m_scans.find(id);
                        if (request != state->m_scans.end()) {
                            const auto root = request->root.lock();
                            const auto node = request->node.lock();
                            if (state->live(root) && node && node->scan == id) {
                                node->active->store(false);
                                node->scan = 0;
                                node->complete = false;
                                node->budget_refused = true;
                                node->error = QStringLiteral("Directory expansion result allocation failed");
                                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
                                node->retry_at = Clock::now() + k_retry_interval;
                                root->expansion_complete = false;
                                state->mark_root(root);
                                state->mark_read(root, true);
                                state->m_work_pending = true;
                            }
                            state->m_scans.erase(request);
                        }
                        state->m_changed.notify_all();
                    }
                    state->m_backend.wake();
                }
                state->publish_reads();
            }
        });
    m_impl->m_worker = std::thread([state = m_impl]() { state->run(); });
}

Direct_registry::~Direct_registry() { m_impl->stop(); }

uint64_t Direct_registry::attach(Callback callback)
{
    const std::lock_guard lock(m_impl->m_mutex);
    const auto id = ++m_impl->m_next_client;
    auto client = std::make_shared<Impl::Client>();
    client->id = id;
    client->callback = std::move(callback);
    m_impl->m_clients.insert(id, std::move(client));
    m_impl->m_read_dirty_clients.insert(id);
    m_impl->publish_reads();
    return id;
}

void Direct_registry::replace(uint64_t client_id, const QList<Watch_spec>& paths, Watch_mode mode,
    std::shared_ptr<path_name::Policy_epoch> policy,
    Native_watcher::Directory_filter filter, bool wait_for_expansion,
    uint64_t eligibility_generation)
{
    QList<path_name::Key> interest_keys;
    interest_keys.reserve(paths.size());
    for (const auto& interest : paths) {
        interest_keys.append(policy->key(interest.path));
    }
    auto& d = *m_impl;
    std::unique_lock lock(d.m_mutex);
    const auto client = d.m_clients.value(client_id);
    if (!client) {
        return; // A concurrent clear may retire this client before admission.
    }
    const bool unchanged = client->requested != 0 && client->mode == mode && client->policy == policy &&
        client->eligibility_generation == eligibility_generation &&
        client->paths.size() == paths.size() &&
        std::equal(client->paths.cbegin(), client->paths.cend(), paths.cbegin(), [](const auto& first, const auto& second) {
            return first.path == second.path && first.maximum_depth == second.maximum_depth;
        });
    if (!unchanged) {
        client->paths = paths;
        client->interest_keys = std::move(interest_keys);
        client->mode = mode;
        client->filter = std::move(filter);
        client->eligibility_generation = eligibility_generation;
        client->policy = std::move(policy);
        ++client->requested;
        d.m_work_pending = true;
        d.m_dirty_clients.insert(client_id);
        d.m_read_dirty_clients.insert(client_id);
    }
    d.publish_reads();
    const auto requested = client->requested;
    d.m_backend.wake();
    if (d.m_worker.get_id() != std::this_thread::get_id()) {
        d.m_changed.wait(lock, [&] {
            return d.m_stopped || !client->active ||
                (client->applied >= requested && (!wait_for_expansion || client->delivered >= requested));
        });
    }
}

void Direct_registry::detach(uint64_t client_id)
{
    auto& d = *m_impl;
    std::unique_lock lock(d.m_mutex);
    const auto client = d.m_clients.take(client_id);
    client->active = false;
    std::shared_ptr<const Impl::Read_view> retired_view;
    {
        const std::lock_guard read_lock(d.m_read_mutex);
        retired_view = d.m_read_views.take(client_id);
    }
    d.m_read_dirty_clients.erase(client_id);
    d.m_changed.notify_all();
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    const auto observer = client->expansion_observer;
#endif
    lock.unlock();
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
    if (observer) {
        observer(Native_watcher::Expansion_stage::WAITING_FOR_RETIREMENT);
    }
#endif
    d.m_scanner->cancel(client_id);
    lock.lock();
    if (d.m_worker.get_id() != std::this_thread::get_id()) {
        d.m_changed.wait(lock, [&] { return client->callbacks == 0; });
    }
    for (const auto& root : client->roots) {
        d.retire_root(root);
    }
    for (const auto& root : client->retiring_roots) {
        d.retire_root(root);
    }
    d.m_dirty_clients.erase(client_id);
    d.m_attempt_clients.erase(client_id);
    d.m_retiring_clients.erase(client_id);
    client->roots.clear();
    client->retiring_roots.clear();
    d.m_work_pending = true;
    d.m_backend.wake();
}

bool Direct_registry::covers(uint64_t client_id, const QString& path) const
{
    return coverage_status(client_id, path).state == Coverage_state::COVERED;
}

Coverage_status Direct_registry::coverage_status(uint64_t client_id, const QString& path) const
{
    const auto view = m_impl->read_view(client_id);
    if (view) {
        if (!view->requested) {
            return {};
        }
        if (const auto root = view->find_root(path)) {
            return root->status;
        }
        if (std::any_of(view->interests.cbegin(), view->interests.cend(), [&](const auto& interest) {
#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
            ++native_test_hooks::coverage_read_candidates;
#endif
            return path_name::matches_key(path, interest);
        }))
        {
            return {};
        }
    }
    return {Coverage_state::FAILED, QStringLiteral("Directory is not an observed interest")};
}

uint64_t Direct_registry::revision(uint64_t client_id, const QString& path) const
{
    if (const auto view = m_impl->read_view(client_id)) {
        if (const auto root = view->find_root(path)) {
            return root->revision;
        }
    }
    return 0;
}

Resource_counts Direct_registry::resource_counts() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    return m_impl->m_resources;
}

#ifdef VNM_FILESYSTEM_OBSERVATION_TEST_HOOKS
bool Direct_registry::maintenance_pending_for_tests() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    const auto& d = *m_impl;
    if (d.m_work_pending || !d.m_dirty_roots.isEmpty() || !d.m_dirty_clients.empty() ||
        !d.m_scan_results.isEmpty() || d.m_backend.resource_counts().detail_bytes != 0)
    {
        return true;
    }
#ifdef Q_OS_WIN
    return !d.m_binding_entries.isEmpty() ||
        (!d.m_identity_due.empty() && d.m_identity_due.begin()->first.first <= Clock::now()) ||
        d.m_windows_applied_plan != d.m_windows_plan_generation;
#else
    return !d.m_native_due.empty() && d.m_native_due.begin()->first.first <= Clock::now();
#endif
}

void Direct_registry::set_maintenance_observer_for_tests(std::function<void(Maintenance_stage)> observer,
    uint64_t exercise_client)
{
    const std::lock_guard lock(m_impl->m_mutex);
    m_impl->m_maintenance_observer = std::move(observer);
    if (exercise_client != 0) {
        // Arm the observer and its work together; the worker must not park
        // before the test thread has submitted its own maintenance request.
        const auto client = m_impl->m_clients.value(exercise_client);
        client->invalidate_content = client->inject_overflow = true;
        m_impl->m_work_pending = true;
        m_impl->m_backend.wake();
    }
}

Direct_registry::Maintenance_counts Direct_registry::maintenance_counts_for_tests(uint64_t client) const
{
    const std::lock_guard lock(m_impl->m_mutex);
    return m_impl->m_clients.value(client)->maintenance;
}

bool Direct_registry::set_directory_available_for_tests(const QString& path, bool available)
{
    const std::lock_guard lock(m_impl->m_mutex);
    for (const auto& entry : m_impl->m_entries) {
        if (path_name::matches_key(path, entry->key)) {
            entry->unavailable = !available;
            entry->retry_at = {};
#ifdef Q_OS_WIN
            m_impl->m_binding_entries.insert(entry->key, entry);
#else
            m_impl->schedule_native(*entry, {});
#endif
            m_impl->mark_entry(*entry);
            m_impl->m_work_pending = true;
            m_impl->m_backend.wake();
            return true;
        }
    }
    return false;
}

QStringList Direct_registry::armed_directories_for_tests() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    QStringList result;
#ifdef Q_OS_WIN
    const auto& entries = m_impl->m_windows_anchors;
#else
    const auto& entries = m_impl->m_entries;
#endif
    for (const auto& entry : entries) {
        if (entry->native_id != 0) {
            result.append(entry->path);
        }
    }
    return result;
}

QStringList Direct_registry::covered_logical_directories_for_tests() const
{
    const std::lock_guard lock(m_impl->m_mutex);
    QStringList result;
    for (const auto& entry : m_impl->m_entries) {
        if (entry->native_id != 0) {
            result.append(entry->path);
        }
    }
    return result;
}

void Direct_registry::invalidate_content_for_tests(uint64_t client)
{
    const std::lock_guard lock(m_impl->m_mutex);
    m_impl->m_clients.value(client)->invalidate_content = true;
    m_impl->m_work_pending = true;
    m_impl->m_backend.wake();
}

void Direct_registry::inject_overflow_for_tests(uint64_t client)
{
    const std::lock_guard lock(m_impl->m_mutex);
    m_impl->m_clients.value(client)->inject_overflow = true;
    m_impl->m_work_pending = true;
    m_impl->m_backend.wake();
}

int Direct_registry::expansion_count_for_tests(uint64_t client) const
{
    const std::lock_guard lock(m_impl->m_mutex);
    return m_impl->m_clients.value(client)->expansions;
}

void Direct_registry::set_expansion_observer_for_tests(uint64_t client,
    std::function<void(Native_watcher::Expansion_stage)> observer)
{
    const std::lock_guard lock(m_impl->m_mutex);
    m_impl->m_clients.value(client)->expansion_observer = std::move(observer);
}

void Direct_registry::set_coverage_for_tests(uint64_t client_id, const QString& path, bool covered)
{
    const std::lock_guard lock(m_impl->m_mutex);
    for (const auto& root : m_impl->m_clients.value(client_id)->roots) {
        if (path_name::matches_key(path, root->key)) {
            root->forced_failure = !covered;
            if (!covered) {
                root->cause = Reconciliation_cause::SOURCE_RECONCILIATION;
            }
            root->covered = covered;
            root->revision = s_next_coverage_revision.fetch_add(1);
            m_impl->mark_root(root);
            m_impl->mark_read(root, true);
            m_impl->publish_reads();
            m_impl->m_work_pending = true;
            m_impl->m_backend.wake();
        }
    }
}
#endif

} // namespace vnm::filesystem_observation::detail
