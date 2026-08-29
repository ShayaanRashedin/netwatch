#pragma once

#include "netwatch/concurrency/BoundedQueue.hpp"
#include "netwatch/detection/Alert.hpp"
#include "netwatch/monitoring/SnapshotDiffer.hpp"
#include "netwatch/storage/SQLiteEventRepository.hpp"

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace netwatch {

class EventWriter {
public:
    EventWriter(
        const std::filesystem::path& databasePath,
        std::size_t queueCapacity
    );

    ~EventWriter();

    EventWriter(const EventWriter&) = delete;
    EventWriter& operator=(const EventWriter&) = delete;

    bool submit(
        SocketEvent event,
        std::vector<Alert> alerts = {}
    );
    void stop();

    [[nodiscard]]
    std::size_t persistedCount() const noexcept;

    [[nodiscard]]
    std::size_t persistedAlertCount() const noexcept;

    [[nodiscard]]
    std::optional<std::string> failure() const;

private:
    struct PendingWrite {
        SocketEvent event;
        std::vector<Alert> alerts;
    };

    void run() noexcept;

    BoundedQueue<PendingWrite> queue_;
    SQLiteEventRepository repository_;
    std::thread worker_;
    std::atomic_size_t persisted_count_ {};
    std::atomic_size_t persisted_alert_count_ {};
    mutable std::mutex failure_mutex_;
    std::optional<std::string> failure_;
};

} // namespace netwatch

