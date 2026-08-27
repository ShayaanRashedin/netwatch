#include "netwatch/core/SocketSnapshot.hpp"

#include <catch2/catch_test_macros.hpp>

#include <vector>

namespace {

netwatch::SocketRecord makeSocket(
    const std::uint64_t inode,
    const std::uint16_t localPort)
{
    netwatch::SocketRecord socket;

    socket.family = netwatch::IpFamily::IPv4;
    socket.protocol = netwatch::TransportProtocol::Tcp;
    socket.local = {"127.0.0.1", localPort};
    socket.remote = {"0.0.0.0", 0U};
    socket.state = netwatch::SocketState::Listen;
    socket.inode = inode;

    return socket;
}

} // namespace

TEST_CASE("Socket snapshot attaches every known owner")
{
    const auto socket = makeSocket(100U, 8080U);

    netwatch::ProcessInfo firstOwner;
    firstOwner.pid = 10;
    firstOwner.name = "first";

    netwatch::ProcessInfo secondOwner;
    secondOwner.pid = 20;
    secondOwner.name = "second";

    netwatch::SocketOwnerMap owners;
    owners[100U] = {firstOwner, secondOwner};

    const auto snapshot = netwatch::makeSocketSnapshot(
        std::vector<netwatch::SocketRecord> {socket},
        owners
    );

    const auto key = netwatch::makeSocketKey(socket);

    REQUIRE(snapshot.contains(key));
    REQUIRE(snapshot.at(key).owners.size() == 2U);
    CHECK(snapshot.at(key).owners[0].pid == 10);
    CHECK(snapshot.at(key).owners[1].pid == 20);
}

TEST_CASE("Socket snapshot keeps sockets with unknown owners")
{
    const auto socket = makeSocket(200U, 22U);

    const auto snapshot = netwatch::makeSocketSnapshot(
        std::vector<netwatch::SocketRecord> {socket},
        {}
    );

    const auto key = netwatch::makeSocketKey(socket);

    REQUIRE(snapshot.contains(key));
    CHECK(snapshot.at(key).owners.empty());
}
