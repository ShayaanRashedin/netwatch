#pragma once

#include "netwatch/detection/Alert.hpp"
#include "netwatch/monitoring/SnapshotDiffer.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace netwatch {

struct StoredSocketEvent {
    std::int64_t id {};
    SocketEvent event;
};

struct StoredAlert {
    std::int64_t id {};
    std::int64_t event_id {};
    Alert alert;
};

struct AlertRuleCount {
    std::string rule_id;
    std::size_t count {};
};

struct StorageSummary {
    std::size_t event_count {};
    std::size_t process_owner_count {};
    std::size_t alert_count {};
    std::size_t low_alert_count {};
    std::size_t medium_alert_count {};
    std::size_t high_alert_count {};
    std::size_t critical_alert_count {};
    std::optional<std::chrono::system_clock::time_point>
        latest_event_at;
    std::optional<std::chrono::system_clock::time_point>
        latest_alert_at;
    std::vector<AlertRuleCount> alerts_by_rule;
};

class SQLiteEventRepository {
public:
    explicit SQLiteEventRepository(
        const std::filesystem::path& databasePath
    );

    ~SQLiteEventRepository();

    SQLiteEventRepository(const SQLiteEventRepository&) = delete;
    SQLiteEventRepository& operator=(
        const SQLiteEventRepository&
    ) = delete;

    void persist(
        const SocketEvent& event,
        const std::vector<Alert>& alerts = {}
    );

    [[nodiscard]]
    std::vector<StoredSocketEvent> recentEvents(
        std::size_t limit
    ) const;

    [[nodiscard]]
    std::vector<StoredAlert> recentAlerts(
        std::size_t limit,
        int minimumRiskScore = 0
    ) const;

    std::size_t deleteEventsOlderThan(
        std::chrono::system_clock::time_point cutoff
    );

    [[nodiscard]]
    std::size_t eventCount() const;

    [[nodiscard]]
    std::size_t processCount() const;

    [[nodiscard]]
    std::size_t alertCount() const;

    [[nodiscard]]
    StorageSummary summary() const;

private:
    void initializeSchema();

    sqlite3* database_ {};
};

} // namespace netwatch

