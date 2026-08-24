#include "netwatch/procfs/ProcNetSocketParser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sstream>

TEST_CASE("IPv4 TCP listener is parsed from procfs")
{
    std::istringstream input {
        "  sl  local_address rem_address   st tx_queue rx_queue "
        "tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1F90 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 123456\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    REQUIRE(sockets.size() == 1);

    const auto& socket = sockets.front();

    CHECK(socket.local.address == "127.0.0.1");
    CHECK(socket.local.port == 8080);

    CHECK(socket.remote.address == "0.0.0.0");
    CHECK(socket.remote.port == 0);

    CHECK(socket.state == netwatch::TcpState::Listen);
    CHECK(socket.inode == 123456);
}

TEST_CASE("Empty socket table produces no records")
{
    std::istringstream input {};

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    CHECK(sockets.empty());
}

TEST_CASE("Socket table containing only header produces no records")
{
    std::istringstream input {
        "  sl  local_address rem_address st tx_queue rx_queue\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    CHECK(sockets.empty());
}

TEST_CASE("Malformed socket row is ignored")
{
    std::istringstream input {
        "header\n"
        "0: 0100007F:1F90 00000000:0000\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    CHECK(sockets.empty());
}

TEST_CASE("Unknown TCP state is preserved as Unknown")
{
    std::istringstream input {
        "header\n"
        "0: 0100007F:1F90 00000000:0000 FF "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 123456\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    REQUIRE(sockets.size() == 1);
    CHECK(sockets.front().state == netwatch::TcpState::Unknown);
}

TEST_CASE("Multiple IPv4 TCP sockets are parsed")
{
    std::istringstream input {
        "header\n"
        "0: 0100007F:1F90 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 123456\n"
        "1: 00000000:0016 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 654321\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    REQUIRE(sockets.size() == 2);
    CHECK(sockets[0].local.port == 8080);
    CHECK(sockets[1].local.port == 22);
}