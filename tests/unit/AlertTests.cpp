#include "netwatch/detection/Alert.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

TEST_CASE("Risk scores map to stable alert severity bands")
{
    CHECK(netwatch::severityForRiskScore(0)
        == netwatch::AlertSeverity::Low);
    CHECK(netwatch::severityForRiskScore(24)
        == netwatch::AlertSeverity::Low);
    CHECK(netwatch::severityForRiskScore(25)
        == netwatch::AlertSeverity::Medium);
    CHECK(netwatch::severityForRiskScore(50)
        == netwatch::AlertSeverity::High);
    CHECK(netwatch::severityForRiskScore(75)
        == netwatch::AlertSeverity::Critical);
    CHECK(netwatch::severityForRiskScore(100)
        == netwatch::AlertSeverity::Critical);
}

TEST_CASE("Risk scores outside the supported range are rejected")
{
    CHECK_THROWS_AS(
        netwatch::severityForRiskScore(-1),
        std::invalid_argument
    );
    CHECK_THROWS_AS(
        netwatch::severityForRiskScore(101),
        std::invalid_argument
    );
}

