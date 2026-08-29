#pragma once

#include "netwatch/detection/Alert.hpp"

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace netwatch {

struct DetectionConfig {
    std::size_t connection_burst_threshold {20U};
    std::chrono::milliseconds connection_burst_window {10'000};
    std::size_t failed_connection_threshold {5U};
    std::chrono::milliseconds failed_connection_window {30'000};
    std::chrono::milliseconds alert_cooldown {30'000};
};

class DetectionEngine {
public:
    explicit DetectionEngine(DetectionConfig config = {});

    [[nodiscard]]
    std::vector<Alert> evaluate(const SocketEvent& event);

private:
    struct ProcessIdentity {
        int pid {};
        std::optional<std::uint64_t> start_time_ticks;

        auto operator<=>(const ProcessIdentity&) const = default;
    };

    using Timeline =
        std::deque<std::chrono::system_clock::time_point>;

    [[nodiscard]]
    bool cooldownAllows(
        const std::string& ruleId,
        const std::string& subject,
        std::chrono::system_clock::time_point observedAt
    );

    static void pruneTimeline(
        Timeline& timeline,
        std::chrono::system_clock::time_point cutoff
    );

    void pruneExpiredState(
        std::chrono::system_clock::time_point observedAt
    );

    DetectionConfig config_;
    std::map<ProcessIdentity, Timeline> connection_bursts_;
    std::map<ProcessIdentity, Timeline> failed_connections_;
    std::map<std::string, std::chrono::system_clock::time_point>
        last_alerts_;
};

} // namespace netwatch

