#include "netwatch/detection/DetectionEngine.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace netwatch {

namespace {

constexpr std::array<std::uint16_t, 8> suspiciousPorts {
    23U,
    2323U,
    4444U,
    5555U,
    6666U,
    6667U,
    9001U,
    31337U
};

bool isLoopback(const std::string_view address)
{
    return address == "::1"
        || address == "0:0:0:0:0:0:0:1"
        || address.starts_with("127.");
}

bool isTemporaryExecutable(const std::string_view executable)
{
    return executable.starts_with("/tmp/")
        || executable.starts_with("/var/tmp/")
        || executable.starts_with("/dev/shm/");
}

bool isDeletedExecutable(const std::string_view executable)
{
    return executable.ends_with(" (deleted)");
}

bool isConnectionAttempt(const SocketEvent& event)
{
    return event.type == SocketEventType::Opened
        && event.observation.socket.protocol
            == TransportProtocol::Tcp
        && event.observation.socket.state
            != SocketState::Listen;
}

bool isFailedConnection(const SocketEvent& event)
{
    if (event.type != SocketEventType::Closed
        || event.observation.socket.protocol
            != TransportProtocol::Tcp) {
        return false;
    }

    const auto state = event.observation.socket.state;
    return state == SocketState::SynSent
        || state == SocketState::SynReceived;
}

std::string processSubject(const ProcessInfo& process)
{
    std::string subject = "pid=" + std::to_string(process.pid);

    if (process.start_time_ticks.has_value()) {
        subject += "@" + std::to_string(*process.start_time_ticks);
    }

    return subject;
}

std::string processEvidence(const ProcessInfo& process)
{
    std::string evidence = processSubject(process);

    if (!process.name.empty()) {
        evidence += " process=" + process.name;
    }
    if (!process.executable.empty()) {
        evidence += " executable=" + process.executable;
    }

    return evidence;
}

std::string endpointEvidence(const SocketRecord& socket)
{
    return "local="
        + socket.local.address
        + ":"
        + std::to_string(socket.local.port)
        + " remote="
        + socket.remote.address
        + ":"
        + std::to_string(socket.remote.port);
}

Alert makeAlert(
    const SocketEvent& event,
    std::string ruleId,
    std::string title,
    std::string reason,
    const int riskScore,
    std::vector<std::string> evidence)
{
    Alert alert;
    alert.detected_at = event.observed_at;
    alert.rule_id = std::move(ruleId);
    alert.title = std::move(title);
    alert.reason = std::move(reason);
    alert.risk_score = riskScore;
    alert.severity = severityForRiskScore(riskScore);
    alert.source_event = event;
    alert.evidence = std::move(evidence);
    return alert;
}

} // namespace

DetectionEngine::DetectionEngine(DetectionConfig config)
    : config_ {config}
{
    if (config_.connection_burst_threshold == 0U
        || config_.failed_connection_threshold == 0U
        || config_.connection_burst_window.count() <= 0
        || config_.failed_connection_window.count() <= 0
        || config_.alert_cooldown.count() < 0) {
        throw std::invalid_argument {
            "detection thresholds and windows must be positive"
        };
    }
}

std::vector<Alert> DetectionEngine::evaluate(
    const SocketEvent& event)
{
    pruneExpiredState(event.observed_at);

    std::vector<Alert> alerts;
    const auto& socket = event.observation.socket;

    if (event.type == SocketEventType::Opened
        && socket.protocol == TransportProtocol::Tcp
        && socket.state == SocketState::Listen) {
        const bool riskyPort = std::find(
            suspiciousPorts.begin(),
            suspiciousPorts.end(),
            socket.local.port
        ) != suspiciousPorts.end();

        const bool publicListener =
            !isLoopback(socket.local.address);

        if (riskyPort) {
            const int riskScore = publicListener ? 70 : 45;
            const std::string subject =
                socket.local.address
                + ":"
                + std::to_string(socket.local.port);

            if (cooldownAllows(
                    "suspicious-listening-port",
                    subject,
                    event.observed_at)) {
                alerts.push_back(makeAlert(
                    event,
                    "suspicious-listening-port",
                    "Suspicious TCP listening port",
                    publicListener
                        ? "A TCP service began listening on a commonly abused port and is reachable beyond loopback."
                        : "A TCP service began listening on a commonly abused port.",
                    riskScore,
                    {
                        endpointEvidence(socket),
                        publicListener
                            ? "listener_scope=non-loopback"
                            : "listener_scope=loopback"
                    }
                ));
            }
        } else if (publicListener
            && socket.local.port >= 49'152) {
            const std::string subject =
                socket.local.address
                + ":"
                + std::to_string(socket.local.port);

            if (cooldownAllows(
                    "unusual-public-listener",
                    subject,
                    event.observed_at)) {
                alerts.push_back(makeAlert(
                    event,
                    "unusual-public-listener",
                    "Unusual public high-port listener",
                    "A process opened a non-loopback TCP listener in the dynamic port range.",
                    35,
                    {
                        endpointEvidence(socket),
                        "listener_scope=non-loopback",
                        "dynamic_port_range=49152-65535"
                    }
                ));
            }
        }
    }

    if (event.type == SocketEventType::Opened) {
        for (const auto& process : event.observation.owners) {
            const std::string subject = processSubject(process);

            if (isTemporaryExecutable(process.executable)
                && cooldownAllows(
                    "temporary-executable-network-activity",
                    subject,
                    event.observed_at)) {
                alerts.push_back(makeAlert(
                    event,
                    "temporary-executable-network-activity",
                    "Network activity from a temporary executable",
                    "A process running from a temporary or shared-memory directory opened a network socket.",
                    85,
                    {
                        processEvidence(process),
                        endpointEvidence(socket),
                        "execution_location=temporary"
                    }
                ));
            }

            if (isDeletedExecutable(process.executable)
                && cooldownAllows(
                    "deleted-executable-network-activity",
                    subject,
                    event.observed_at)) {
                alerts.push_back(makeAlert(
                    event,
                    "deleted-executable-network-activity",
                    "Network activity from a deleted executable",
                    "A running process whose executable has been deleted opened a network socket.",
                    80,
                    {
                        processEvidence(process),
                        endpointEvidence(socket),
                        "executable_state=deleted"
                    }
                ));
            }
        }
    }

    if (isConnectionAttempt(event)) {
        for (const auto& process : event.observation.owners) {
            const ProcessIdentity identity {
                process.pid,
                process.start_time_ticks
            };

            auto& timeline = connection_bursts_[identity];
            pruneTimeline(
                timeline,
                event.observed_at
                    - config_.connection_burst_window
            );
            timeline.push_back(event.observed_at);

            const std::string subject = processSubject(process);

            if (timeline.size()
                    >= config_.connection_burst_threshold
                && cooldownAllows(
                    "rapid-connection-burst",
                    subject,
                    event.observed_at)) {
                alerts.push_back(makeAlert(
                    event,
                    "rapid-connection-burst",
                    "Rapid outbound connection burst",
                    "One process opened many TCP connections inside a short rolling window.",
                    60,
                    {
                        processEvidence(process),
                        "connection_count="
                            + std::to_string(timeline.size()),
                        "window_ms="
                            + std::to_string(
                                config_.connection_burst_window.count()
                            ),
                        endpointEvidence(socket)
                    }
                ));
            }
        }
    }

    if (isFailedConnection(event)) {
        for (const auto& process : event.observation.owners) {
            const ProcessIdentity identity {
                process.pid,
                process.start_time_ticks
            };

            auto& timeline = failed_connections_[identity];
            pruneTimeline(
                timeline,
                event.observed_at
                    - config_.failed_connection_window
            );
            timeline.push_back(event.observed_at);

            const std::string subject = processSubject(process);

            if (timeline.size()
                    >= config_.failed_connection_threshold
                && cooldownAllows(
                    "repeated-failed-connections",
                    subject,
                    event.observed_at)) {
                alerts.push_back(makeAlert(
                    event,
                    "repeated-failed-connections",
                    "Repeated failed TCP connections",
                    "One process accumulated multiple incomplete TCP handshakes inside a rolling window.",
                    55,
                    {
                        processEvidence(process),
                        "failed_connection_count="
                            + std::to_string(timeline.size()),
                        "window_ms="
                            + std::to_string(
                                config_.failed_connection_window.count()
                            ),
                        endpointEvidence(socket)
                    }
                ));
            }
        }
    }

    return alerts;
}

bool DetectionEngine::cooldownAllows(
    const std::string& ruleId,
    const std::string& subject,
    const std::chrono::system_clock::time_point observedAt)
{
    const std::string key = ruleId + ':' + subject;
    const auto previous = last_alerts_.find(key);

    if (previous != last_alerts_.end()
        && observedAt - previous->second < config_.alert_cooldown) {
        return false;
    }

    last_alerts_.insert_or_assign(key, observedAt);
    return true;
}

void DetectionEngine::pruneTimeline(
    Timeline& timeline,
    const std::chrono::system_clock::time_point cutoff)
{
    while (!timeline.empty() && timeline.front() < cutoff) {
        timeline.pop_front();
    }
}

void DetectionEngine::pruneExpiredState(
    const std::chrono::system_clock::time_point observedAt)
{
    const auto pruneMap = [observedAt](
        auto& timelines,
        const std::chrono::milliseconds window) {
        const auto cutoff = observedAt - window;

        for (auto item = timelines.begin();
             item != timelines.end();) {
            pruneTimeline(item->second, cutoff);

            if (item->second.empty()) {
                item = timelines.erase(item);
            } else {
                ++item;
            }
        }
    };

    pruneMap(connection_bursts_, config_.connection_burst_window);
    pruneMap(failed_connections_, config_.failed_connection_window);

    for (auto item = last_alerts_.begin();
         item != last_alerts_.end();) {
        if (observedAt - item->second >= config_.alert_cooldown) {
            item = last_alerts_.erase(item);
        } else {
            ++item;
        }
    }
}

} // namespace netwatch

