#include "netwatch/procfs/ProcNetSocketParser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sstream>

TEST_CASE("IPv4 TCP listener is parsed from procfs")
{
    std::istringstream input {
        "header\n"
        "0: 0100007F:1F90 00000000:0000 0A "
        "0000000A:0000000B 00:00000000 00000000 "
        "1000 0 123456\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    REQUIRE(sockets.size() == 1U);

    const auto& socket = sockets.front();

    CHECK(socket.family == netwatch::IpFamily::IPv4);
    CHECK(socket.protocol == netwatch::TransportProtocol::Tcp);
    CHECK(socket.local.address == "127.0.0.1");
    CHECK(socket.local.port == 8080U);
    CHECK(socket.remote.address == "0.0.0.0");
    CHECK(socket.remote.port == 0U);
    CHECK(socket.state == netwatch::SocketState::Listen);
    CHECK(socket.inode == 123456U);
    CHECK(socket.tx_queue_bytes == 10U);
    CHECK(socket.rx_queue_bytes == 11U);
}

TEST_CASE("IPv4 UDP socket is parsed as unconnected")
{
    std::istringstream input {
        "header\n"
        "0: 00000000:14E9 00000000:0000 07 "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 222222\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Udp
    );

    REQUIRE(sockets.size() == 1U);

    const auto& socket = sockets.front();

    CHECK(socket.protocol == netwatch::TransportProtocol::Udp);
    CHECK(socket.local.address == "0.0.0.0");
    CHECK(socket.local.port == 5353U);
    CHECK(socket.state == netwatch::SocketState::Unconnected);
    CHECK(socket.inode == 222222U);
}

TEST_CASE("IPv6 TCP listener is parsed from procfs")
{
    std::istringstream input {
        "header\n"
        "0: 00000000000000000000000001000000:1F90 "
        "00000000000000000000000000000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 333333\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv6,
        netwatch::TransportProtocol::Tcp
    );

    REQUIRE(sockets.size() == 1U);

    const auto& socket = sockets.front();

    CHECK(socket.family == netwatch::IpFamily::IPv6);
    CHECK(socket.local.address == "::1");
    CHECK(socket.local.port == 8080U);
    CHECK(socket.remote.address == "::");
    CHECK(socket.state == netwatch::SocketState::Listen);
    CHECK(socket.inode == 333333U);
}

TEST_CASE("IPv6 UDP socket is parsed from procfs")
{
    std::istringstream input {
        "header\n"
        "0: 00000000000000000000000001000000:0035 "
        "00000000000000000000000000000000:0000 07 "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 444444\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv6,
        netwatch::TransportProtocol::Udp
    );

    REQUIRE(sockets.size() == 1U);

    const auto& socket = sockets.front();

    CHECK(socket.family == netwatch::IpFamily::IPv6);
    CHECK(socket.protocol == netwatch::TransportProtocol::Udp);
    CHECK(socket.local.address == "::1");
    CHECK(socket.local.port == 53U);
    CHECK(socket.state == netwatch::SocketState::Unconnected);
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
    std::istringstream input {"header\n"};

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    CHECK(sockets.empty());
}

TEST_CASE("Malformed socket rows are ignored")
{
    std::istringstream input {
        "header\n"
        "0: 0100007F:1F90 00000000:0000\n"
        "1: invalid:0016 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 123456\n"
    };

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        input,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    CHECK(sockets.empty());
}

TEST_CASE("Unknown TCP state is preserved as unknown")
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

    REQUIRE(sockets.size() == 1U);
    CHECK(sockets.front().state == netwatch::SocketState::Unknown);
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

    REQUIRE(sockets.size() == 2U);
    CHECK(sockets[0].local.port == 8080U);
    CHECK(sockets[1].local.port == 22U);
}
