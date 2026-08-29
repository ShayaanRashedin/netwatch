#include "netwatch/detection/DetectionEngine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

netwatch::SocketEvent makeDetectionEvent(
    const netwatch::SocketEventType type,
    const netwatch::SocketState state,
    const std::uint16_t localPort,
    const std::int64_t observedMilliseconds,
    const std::string& localAddress = "127.0.0.1",
    const int pid = 100,
    const std::uint64_t startTicks = 500U,
    const std::string& executable = "/usr/bin/test-process")
{
    netwatch::SocketEvent event;
    event.type = type;
    event.observed_at = std::chrono::system_clock::time_point {
        std::chrono::milliseconds {observedMilliseconds}
    };

    auto& socket = event.observation.socket;
    socket.family = netwatch::IpFamily::IPv4;
    socket.protocol = netwatch::TransportProtocol::Tcp;
    socket.local = {localAddress, localPort};
    socket.remote = {"203.0.113.10", 443U};
    socket.state = state;
    socket.inode = static_cast<std::uint64_t>(
        observedMilliseconds + 10'000
    );

    netwatch::ProcessInfo owner;
    owner.pid = pid;
    owner.start_time_ticks = startTicks;
    owner.name = "test-process";
    owner.executable = executable;
    event.observation.owners.push_back(owner);

    return event;
}

const netwatch::Alert* findAlert(
    const std::vector<netwatch::Alert>& alerts,
    const std::string& ruleId)
{
    const auto result = std::find_if(
        alerts.begin(),
        alerts.end(),
        [&ruleId](const netwatch::Alert& alert) {
            return alert.rule_id == ruleId;
        }
    );

    return result == alerts.end() ? nullptr : &*result;
}

} // namespace

TEST_CASE("Detection engine rejects invalid rolling thresholds")
{
    netwatch::DetectionConfig config;
    config.connection_burst_threshold = 0U;

    CHECK_THROWS(netwatch::DetectionEngine {config});
}

TEST_CASE("Public listener on a commonly abused port produces a high alert")
{
    netwatch::DetectionEngine engine;

    const auto alerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Listen,
        4444U,
        1000,
        "0.0.0.0"
    ));

    const auto* alert = findAlert(
        alerts,
        "suspicious-listening-port"
    );

    REQUIRE(alert != nullptr);
    CHECK(alert->risk_score == 70);
    CHECK(alert->severity == netwatch::AlertSeverity::High);
    CHECK_FALSE(alert->reason.empty());
    CHECK(alert->evidence.size() >= 2U);
}

TEST_CASE("Loopback suspicious listener receives a lower contextual score")
{
    netwatch::DetectionEngine engine;

    const auto alerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Listen,
        4444U,
        1000
    ));

    const auto* alert = findAlert(
        alerts,
        "suspicious-listening-port"
    );

    REQUIRE(alert != nullptr);
    CHECK(alert->risk_score == 45);
    CHECK(alert->severity == netwatch::AlertSeverity::Medium);
}

TEST_CASE("Non-loopback dynamic listener produces an unusual-port alert")
{
    netwatch::DetectionEngine engine;

    const auto alerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Listen,
        55'000U,
        1000,
        "192.0.2.20"
    ));

    const auto* alert = findAlert(
        alerts,
        "unusual-public-listener"
    );

    REQUIRE(alert != nullptr);
    CHECK(alert->risk_score == 35);
    CHECK(alert->severity == netwatch::AlertSeverity::Medium);
}

TEST_CASE("Temporary deleted executable produces explainable critical alerts")
{
    netwatch::DetectionEngine engine;

    const auto alerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        40'000U,
        1000,
        "127.0.0.1",
        222,
        600U,
        "/tmp/agent (deleted)"
    ));

    const auto* temporary = findAlert(
        alerts,
        "temporary-executable-network-activity"
    );
    const auto* deleted = findAlert(
        alerts,
        "deleted-executable-network-activity"
    );

    REQUIRE(temporary != nullptr);
    REQUIRE(deleted != nullptr);
    CHECK(temporary->severity == netwatch::AlertSeverity::Critical);
    CHECK(deleted->severity == netwatch::AlertSeverity::Critical);
    CHECK_FALSE(temporary->evidence.empty());
    CHECK_FALSE(deleted->evidence.empty());
}

TEST_CASE("Rapid connection burst triggers once inside its cooldown")
{
    netwatch::DetectionConfig config;
    config.connection_burst_threshold = 3U;
    config.connection_burst_window = std::chrono::milliseconds {1000};
    config.alert_cooldown = std::chrono::milliseconds {5000};

    netwatch::DetectionEngine engine {config};

    CHECK(engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        40'000U,
        0
    )).empty());

    CHECK(engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        40'001U,
        100
    )).empty());

    const auto thresholdAlerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        40'002U,
        200
    ));

    const auto* burst = findAlert(
        thresholdAlerts,
        "rapid-connection-burst"
    );
    REQUIRE(burst != nullptr);
    CHECK(burst->risk_score == 60);

    const auto cooldownAlerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        40'003U,
        300
    ));

    CHECK(findAlert(
        cooldownAlerts,
        "rapid-connection-burst"
    ) == nullptr);
}

TEST_CASE("Repeated incomplete handshakes trigger a failed-connection alert")
{
    netwatch::DetectionConfig config;
    config.failed_connection_threshold = 2U;
    config.failed_connection_window = std::chrono::milliseconds {2000};

    netwatch::DetectionEngine engine {config};

    CHECK(engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Closed,
        netwatch::SocketState::SynSent,
        41'000U,
        0
    )).empty());

    const auto alerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Closed,
        netwatch::SocketState::SynSent,
        41'001U,
        500
    ));

    const auto* failed = findAlert(
        alerts,
        "repeated-failed-connections"
    );

    REQUIRE(failed != nullptr);
    CHECK(failed->risk_score == 55);
    CHECK(failed->severity == netwatch::AlertSeverity::High);
}

TEST_CASE("PID reuse does not combine behavior from different processes")
{
    netwatch::DetectionConfig config;
    config.connection_burst_threshold = 2U;

    netwatch::DetectionEngine engine {config};

    CHECK(engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        42'000U,
        0,
        "127.0.0.1",
        777,
        100U
    )).empty());

    CHECK(engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Established,
        42'001U,
        100,
        "127.0.0.1",
        777,
        200U
    )).empty());
}

TEST_CASE("Ordinary listener does not produce an alert")
{
    netwatch::DetectionEngine engine;

    const auto alerts = engine.evaluate(makeDetectionEvent(
        netwatch::SocketEventType::Opened,
        netwatch::SocketState::Listen,
        8080U,
        1000
    ));

    CHECK(alerts.empty());
}

