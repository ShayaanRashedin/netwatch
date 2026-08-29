#pragma once

#include "netwatch/monitoring/SnapshotDiffer.hpp"

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace netwatch {

enum class AlertSeverity {
    Low,
    Medium,
    High,
    Critical
};

struct Alert {
    std::chrono::system_clock::time_point detected_at;
    std::string rule_id;
    std::string title;
    std::string reason;
    int risk_score {};
    AlertSeverity severity {AlertSeverity::Low};
    SocketEvent source_event;
    std::vector<std::string> evidence;
};

[[nodiscard]]
AlertSeverity severityForRiskScore(int riskScore);

[[nodiscard]]
std::string_view alertSeverityToString(AlertSeverity severity);

[[nodiscard]]
AlertSeverity alertSeverityFromString(std::string_view value);

} // namespace netwatch

