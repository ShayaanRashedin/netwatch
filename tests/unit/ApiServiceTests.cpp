#include "netwatch/api/ApiService.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

namespace {

class ApiDatabase {
public:
    ApiDatabase()
    {
        static std::atomic_uint64_t sequence {};

        path_ = std::filesystem::temp_directory_path()
            / ("netwatch-api-test-"
                + std::to_string(++sequence)
                + "-"
                + std::to_string(
                    std::chrono::steady_clock::now()
                        .time_since_epoch()
                        .count()
                )
                + ".db");
    }

    ~ApiDatabase()
    {
        std::error_code error;
        std::filesystem::remove(path_, error);
        std::filesystem::remove(path_.string() + "-wal", error);
        std::filesystem::remove(path_.string() + "-shm", error);
    }

    [[nodiscard]]
    const std::filesystem::path& path() const
    {
        return path_;
    }

private:
    std::filesystem::path path_;
};

netwatch::SocketEvent apiEvent(
    const std::int64_t observedSeconds,
    const std::uint64_t inode,
    const std::uint16_t port)
{
    netwatch::SocketEvent event;
    event.type = netwatch::SocketEventType::Opened;
    event.observed_at = std::chrono::system_clock::time_point {
        std::chrono::seconds {observedSeconds}
    };

    auto& socket = event.observation.socket;
    socket.family = netwatch::IpFamily::IPv4;
    socket.protocol = netwatch::TransportProtocol::Tcp;
    socket.local = {"0.0.0.0", port};
    socket.remote = {"0.0.0.0", 0U};
    socket.state = netwatch::SocketState::Listen;
    socket.inode = inode;

    netwatch::ProcessInfo owner;
    owner.pid = static_cast<int>(inode);
    owner.start_time_ticks = inode * 10U;
    owner.uid = 1000U;
    owner.name = "api-test";
    owner.executable = "/usr/bin/api-test";
    event.observation.owners.push_back(owner);

    return event;
}

netwatch::Alert apiAlert(
    const netwatch::SocketEvent& event,
    std::string ruleId,
    const int riskScore)
{
    netwatch::Alert alert;
    alert.detected_at = event.observed_at;
    alert.rule_id = std::move(ruleId);
    alert.title = "API test alert";
    alert.reason = "Test the JSON presentation layer";
    alert.risk_score = riskScore;
    alert.severity = netwatch::severityForRiskScore(riskScore);
    alert.source_event = event;
    alert.evidence = {"api_test=true"};
    return alert;
}

void seedApiDatabase(const std::filesystem::path& path)
{
    netwatch::SQLiteEventRepository repository {path};

    const auto first = apiEvent(10, 101U, 4444U);
    const auto second = apiEvent(20, 202U, 55'000U);

    repository.persist(first, {
        apiAlert(first, "suspicious-listening-port", 70)
    });
    repository.persist(second, {
        apiAlert(second, "temporary-executable-network-activity", 85)
    });
}

nlohmann::json parseBody(const netwatch::ApiResponse& response)
{
    REQUIRE(response.status == 200);
    return nlohmann::json::parse(response.body);
}

} // namespace

TEST_CASE("API health response identifies the service")
{
    ApiDatabase database;
    netwatch::ApiService service {database.path()};

    const auto body = parseBody(service.health());

    CHECK(body.at("status") == "ok");
    CHECK(body.at("service") == "netwatch-api");
    CHECK(body.at("version") == NETWATCH_VERSION);
    CHECK(body.at("generated_at").is_string());
}

TEST_CASE("API summary exposes totals, severity bands, and rule counts")
{
    ApiDatabase database;
    seedApiDatabase(database.path());
    netwatch::ApiService service {database.path()};

    const auto body = parseBody(service.summary());

    CHECK(body.at("event_count") == 2);
    CHECK(body.at("process_owner_count") == 2);
    CHECK(body.at("alert_count") == 2);
    CHECK(body.at("alerts_by_severity").at("HIGH") == 1);
    CHECK(body.at("alerts_by_severity").at("CRITICAL") == 1);
    REQUIRE(body.at("alerts_by_rule").size() == 2U);
    CHECK(body.at("latest_event_at").is_string());
    CHECK(body.at("latest_alert_at").is_string());
}

TEST_CASE("API events response is bounded and contains process context")
{
    ApiDatabase database;
    seedApiDatabase(database.path());
    netwatch::ApiService service {database.path()};

    const auto body = parseBody(service.events(1U));

    CHECK(body.at("count") == 1);
    CHECK(body.at("limit") == 1);

    const auto& event = body.at("events").at(0);
    CHECK(event.at("inode") == 202);
    CHECK(event.at("local").at("port") == 55'000);
    CHECK(event.at("type") == "OPENED");
    REQUIRE(event.at("owners").size() == 1U);
    CHECK(event.at("owners").at(0).at("name") == "api-test");
}

TEST_CASE("API alerts response applies minimum risk filtering")
{
    ApiDatabase database;
    seedApiDatabase(database.path());
    netwatch::ApiService service {database.path()};

    const auto body = parseBody(service.alerts(10U, 80));

    CHECK(body.at("count") == 1);
    CHECK(body.at("minimum_risk_score") == 80);

    const auto& alert = body.at("alerts").at(0);
    CHECK(alert.at("risk_score") == 85);
    CHECK(alert.at("severity") == "CRITICAL");
    CHECK(alert.at("rule_id")
        == "temporary-executable-network-activity");
    CHECK(alert.at("evidence").at(0) == "api_test=true");
    CHECK(alert.at("source_event").at("inode") == 202);
}

TEST_CASE("API connection observes events committed by a separate writer")
{
    ApiDatabase database;
    netwatch::ApiService service {database.path()};

    {
        netwatch::SQLiteEventRepository writer {database.path()};
        const auto event = apiEvent(30, 303U, 8080U);
        writer.persist(event);
    }

    const auto body = parseBody(service.summary());
    CHECK(body.at("event_count") == 1);
    CHECK(body.at("alert_count") == 0);
}

