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