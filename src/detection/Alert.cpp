#include "netwatch/detection/Alert.hpp"

#include <stdexcept>
#include <string>

namespace netwatch {

AlertSeverity severityForRiskScore(const int riskScore)
{
    if (riskScore < 0 || riskScore > 100) {
        throw std::invalid_argument {
            "risk score must be between 0 and 100"
        };
    }

    if (riskScore >= 75) {
        return AlertSeverity::Critical;
    }
    if (riskScore >= 50) {
        return AlertSeverity::High;
    }
    if (riskScore >= 25) {
        return AlertSeverity::Medium;
    }

    return AlertSeverity::Low;
}

std::string_view alertSeverityToString(const AlertSeverity severity)
{
    switch (severity) {
    case AlertSeverity::Low:
        return "LOW";
    case AlertSeverity::Medium:
        return "MEDIUM";
    case AlertSeverity::High:
        return "HIGH";
    case AlertSeverity::Critical:
        return "CRITICAL";
    }

    return "UNKNOWN";
}

AlertSeverity alertSeverityFromString(const std::string_view value)
{
    if (value == "LOW") return AlertSeverity::Low;
    if (value == "MEDIUM") return AlertSeverity::Medium;
    if (value == "HIGH") return AlertSeverity::High;
    if (value == "CRITICAL") return AlertSeverity::Critical;

    throw std::runtime_error {
        "Unknown alert severity in database: "
        + std::string {value}
    };
}

} // namespace netwatch

