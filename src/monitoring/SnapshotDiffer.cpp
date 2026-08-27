#include "netwatch/monitoring/SnapshotDiffer.hpp"

#include <utility>

namespace netwatch {

std::vector<SocketEvent> SnapshotDiffer::diff(
    const SocketSnapshot& previous,
    const SocketSnapshot& current,
    const std::chrono::system_clock::time_point observedAt) const
{
    std::vector<SocketEvent> events;

    for (const auto& [key, observation] : current) {
        const auto oldObservation = previous.find(key);

        if (oldObservation == previous.end()) {
            events.push_back(SocketEvent {
                SocketEventType::Opened,
                observedAt,
                observation,
                std::nullopt
            });

            continue;
        }

        if (oldObservation->second.socket.state
            != observation.socket.state) {
            events.push_back(SocketEvent {
                SocketEventType::StateChanged,
                observedAt,
                observation,
                oldObservation->second.socket.state
            });
        }
    }

    for (const auto& [key, observation] : previous) {
        if (current.contains(key)) {
            continue;
        }

        events.push_back(SocketEvent {
            SocketEventType::Closed,
            observedAt,
            observation,
            std::nullopt
        });
    }

    return events;
}

} // namespace netwatch
