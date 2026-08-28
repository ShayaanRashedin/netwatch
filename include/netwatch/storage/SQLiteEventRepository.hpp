#pragma once

#include "netwatch/monitoring/SnapshotDiffer.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

struct sqlite3;

namespace netwatch {

struct StoredSocketEvent {
    std::int64_t id {};
    SocketEvent event;
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

    void persist(const SocketEvent& event);

    [[nodiscard]]
    std::vector<StoredSocketEvent> recentEvents(
        std::size_t limit
    ) const;

    std::size_t deleteEventsOlderThan(
        std::chrono::system_clock::time_point cutoff
    );

    [[nodiscard]]
    std::size_t eventCount() const;

    [[nodiscard]]
    std::size_t processCount() const;

private:
    void initializeSchema();

    sqlite3* database_ {};
};

} // namespace netwatch

