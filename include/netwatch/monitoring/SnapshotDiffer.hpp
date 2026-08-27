#pragma once

#include "netwatch/core/SocketSnapshot.hpp"

#include <chrono>
#include <optional>
#include <vector>

namespace netwatch {

enum class SocketEventType {
    Opened,
    Closed,
    StateChanged
};

struct SocketEvent {
    SocketEventType type {};
    std::chrono::system_clock::time_point observed_at;
    ObservedSocket observation;
    std::optional<SocketState> previous_state;
};

class SnapshotDiffer {
public:
    [[nodiscard]]
    std::vector<SocketEvent> diff(
        const SocketSnapshot& previous,
        const SocketSnapshot& current,
        std::chrono::system_clock::time_point observedAt
    ) const;
};

} // namespace netwatch
