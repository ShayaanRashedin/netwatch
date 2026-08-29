#include "netwatch/api/ApiService.hpp"

#include "netwatch/detection/Alert.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace netwatch {

namespace {

using Json = nlohmann::json;

std::string formatTimestamp(
    const std::chrono::system_clock::time_point timePoint)
{
    const std::time_t rawTime =
        std::chrono::system_clock::to_time_t(timePoint);
    std::tm utcTime {};

    if (::gmtime_r(&rawTime, &utcTime) == nullptr) {
        return "unknown-time";
    }

    std::ostringstream output;
    output << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

Json optionalTimestamp(
    const std::optional<std::chrono::system_clock::time_point>& value)
{
    if (!value.has_value()) {
        return nullptr;
    }

    return formatTimestamp(*value);
}

std::string_view eventTypeToString(const SocketEventType type)
{
    switch (type) {
    case SocketEventType::Opened:
        return "OPENED";
    case SocketEventType::Closed:
        return "CLOSED";
    case SocketEventType::StateChanged:
        return "STATE_CHANGED";
    }

    return "UNKNOWN";
}

std::string_view familyToString(const IpFamily family)
{
    switch (family) {
    case IpFamily::IPv4:
        return "IPv4";
    case IpFamily::IPv6:
        return "IPv6";
    }

    return "UNKNOWN";
}

std::string_view protocolToString(const TransportProtocol protocol)
{
    switch (protocol) {
    case TransportProtocol::Tcp:
        return "TCP";
    case TransportProtocol::Udp:
        return "UDP";
    }

    return "UNKNOWN";
}

std::string_view stateToString(const SocketState state)
{
    switch (state) {
    case SocketState::Established:
        return "ESTABLISHED";
    case SocketState::SynSent:
        return "SYN_SENT";
    case SocketState::SynReceived:
        return "SYN_RECV";
    case SocketState::FinWait1:
        return "FIN_WAIT1";
    case SocketState::FinWait2:
        return "FIN_WAIT2";
    case SocketState::TimeWait:
        return "TIME_WAIT";
    case SocketState::Closed:
        return "CLOSED";
    case SocketState::CloseWait:
        return "CLOSE_WAIT";
    case SocketState::LastAck:
        return "LAST_ACK";
    case SocketState::Listen:
        return "LISTEN";
    case SocketState::Closing:
        return "CLOSING";
    case SocketState::NewSynReceived:
        return "NEW_SYN_RECV";
    case SocketState::Unconnected:
        return "UNCONN";
    case SocketState::Unknown:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}

Json processToJson(const ProcessInfo& process)
{
    Json result {
        {"pid", process.pid},
        {"username", process.username},
        {"name", process.name},
        {"executable", process.executable},
        {"command_line", process.command_line}
    };

    if (process.uid.has_value()) {
        result["uid"] = *process.uid;
    } else {
        result["uid"] = nullptr;
    }

    if (process.start_time_ticks.has_value()) {
        result["start_time_ticks"] = *process.start_time_ticks;
    } else {
        result["start_time_ticks"] = nullptr;
    }

    return result;
}

Json eventToJson(
    const SocketEvent& event,
    const std::optional<std::int64_t> id = std::nullopt)
{
    const auto& socket = event.observation.socket;

    Json owners = Json::array();
    for (const auto& process : event.observation.owners) {
        owners.push_back(processToJson(process));
    }

    Json result {
        {"observed_at", formatTimestamp(event.observed_at)},
        {"type", std::string {eventTypeToString(event.type)}},
        {"family", std::string {familyToString(socket.family)}},
        {"protocol", std::string {
            protocolToString(socket.protocol)
        }},
        {"local", {
            {"address", socket.local.address},
            {"port", socket.local.port}
        }},
        {"remote", {
            {"address", socket.remote.address},
            {"port", socket.remote.port}
        }},
        {"state", std::string {stateToString(socket.state)}},
        {"inode", socket.inode},
        {"tx_queue_bytes", socket.tx_queue_bytes},
        {"rx_queue_bytes", socket.rx_queue_bytes},
        {"owners", std::move(owners)}
    };

    if (id.has_value()) {
        result["id"] = *id;
    } else {
        result["id"] = nullptr;
    }

    if (event.previous_state.has_value()) {
        result["previous_state"] =
            std::string {stateToString(*event.previous_state)};
    } else {
        result["previous_state"] = nullptr;
    }

    return result;
}

Json alertToJson(const StoredAlert& stored)
{
    const auto& alert = stored.alert;

    return Json {
        {"id", stored.id},
        {"event_id", stored.event_id},
        {"detected_at", formatTimestamp(alert.detected_at)},
        {"rule_id", alert.rule_id},
        {"title", alert.title},
        {"reason", alert.reason},
        {"risk_score", alert.risk_score},
        {"severity", std::string {
            alertSeverityToString(alert.severity)
        }},
        {"evidence", alert.evidence},
        {"source_event", eventToJson(
            alert.source_event,
            stored.event_id
        )}
    };
}

ApiResponse jsonResponse(Json body)
{
    return ApiResponse {200, body.dump()};
}

} // namespace

ApiService::ApiService(const std::filesystem::path& databasePath)
    : repository_ {databasePath}
{
}

ApiResponse ApiService::health() const
{
    return jsonResponse(Json {
        {"status", "ok"},
        {"service", "netwatch-api"},
        {"version", "0.5.0"},
        {"generated_at", formatTimestamp(
            std::chrono::system_clock::now()
        )}
    });
}

ApiResponse ApiService::summary() const
{
    const auto summary = repository_.summary();
    Json rules = Json::array();

    for (const auto& rule : summary.alerts_by_rule) {
        rules.push_back(Json {
            {"rule_id", rule.rule_id},
            {"count", rule.count}
        });
    }

    return jsonResponse(Json {
        {"generated_at", formatTimestamp(
            std::chrono::system_clock::now()
        )},
        {"event_count", summary.event_count},
        {"process_owner_count", summary.process_owner_count},
        {"alert_count", summary.alert_count},
        {"alerts_by_severity", {
            {"LOW", summary.low_alert_count},
            {"MEDIUM", summary.medium_alert_count},
            {"HIGH", summary.high_alert_count},
            {"CRITICAL", summary.critical_alert_count}
        }},
        {"latest_event_at", optionalTimestamp(
            summary.latest_event_at
        )},
        {"latest_alert_at", optionalTimestamp(
            summary.latest_alert_at
        )},
        {"alerts_by_rule", std::move(rules)}
    });
}

ApiResponse ApiService::events(const std::size_t limit) const
{
    Json events = Json::array();

    for (const auto& stored : repository_.recentEvents(limit)) {
        events.push_back(eventToJson(stored.event, stored.id));
    }

    return jsonResponse(Json {
        {"count", events.size()},
        {"limit", limit},
        {"events", std::move(events)}
    });
}

ApiResponse ApiService::alerts(
    const std::size_t limit,
    const int minimumRiskScore) const
{
    Json alerts = Json::array();

    for (const auto& stored : repository_.recentAlerts(
            limit,
            minimumRiskScore)) {
        alerts.push_back(alertToJson(stored));
    }

    return jsonResponse(Json {
        {"count", alerts.size()},
        {"limit", limit},
        {"minimum_risk_score", minimumRiskScore},
        {"alerts", std::move(alerts)}
    });
}

} // namespace netwatch

