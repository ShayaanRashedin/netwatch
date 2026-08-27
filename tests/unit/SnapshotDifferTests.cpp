#include "netwatch/monitoring/SnapshotDiffer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>

namespace {

netwatch::SocketRecord makeSocket(
    const std::uint64_t inode,
    const std::uint16_t localPort,
    const netwatch::SocketState state =
        netwatch::SocketState::Listen)
{
    netwatch::SocketRecord socket;

    socket.family = netwatch::IpFamily::IPv4;
    socket.protocol = netwatch::TransportProtocol::Tcp;
    socket.local = {"127.0.0.1", localPort};
    socket.remote = {"0.0.0.0", 0U};
    socket.state = state;
    socket.inode = inode;

    return socket;
}

netwatch::SocketSnapshot snapshotOf(
    const std::vector<netwatch::SocketRecord>& sockets,
    const netwatch::SocketOwnerMap& owners = {})
{
    return netwatch::makeSocketSnapshot(
        sockets,
        owners
    );
}

} // namespace

TEST_CASE("New socket produces an opened event")
{
    const auto socket = makeSocket(100U, 8080U);
    const auto observedAt =
        std::chrono::system_clock::time_point {
            std::chrono::seconds {42}
        };

    netwatch::SnapshotDiffer differ;

    const auto events = differ.diff(
        {},
        snapshotOf({socket}),
        observedAt
    );

    REQUIRE(events.size() == 1U);
    CHECK(events.front().type
        == netwatch::SocketEventType::Opened);
    CHECK(events.front().observed_at == observedAt);
    CHECK(events.front().observation.socket.inode == 100U);
    CHECK_FALSE(events.front().previous_state.has_value());
}

TEST_CASE("Removed socket produces a closed event with prior owners")
{
    const auto socket = makeSocket(200U, 22U);

    netwatch::ProcessInfo owner;
    owner.pid = 77;
    owner.name = "sshd";

    netwatch::SocketOwnerMap owners;
    owners[200U] = {owner};

    netwatch::SnapshotDiffer differ;

    const auto events = differ.diff(
        snapshotOf({socket}, owners),
        {},
        std::chrono::system_clock::time_point {}
    );

    REQUIRE(events.size() == 1U);
    CHECK(events.front().type
        == netwatch::SocketEventType::Closed);
    REQUIRE(events.front().observation.owners.size() == 1U);
    CHECK(events.front().observation.owners.front().pid == 77);
}

TEST_CASE("Unchanged socket produces no event")
{
    const auto socket = makeSocket(300U, 443U);
    const auto snapshot = snapshotOf({socket});

    netwatch::SnapshotDiffer differ;

    const auto events = differ.diff(
        snapshot,
        snapshot,
        std::chrono::system_clock::time_point {}
    );

    CHECK(events.empty());
}

TEST_CASE("Socket state transition produces a state-changed event")
{
    const auto previousSocket = makeSocket(
        400U,
        5000U,
        netwatch::SocketState::SynSent
    );

    const auto currentSocket = makeSocket(
        400U,
        5000U,
        netwatch::SocketState::Established
    );

    netwatch::SnapshotDiffer differ;

    const auto events = differ.diff(
        snapshotOf({previousSocket}),
        snapshotOf({currentSocket}),
        std::chrono::system_clock::time_point {}
    );

    REQUIRE(events.size() == 1U);
    CHECK(events.front().type
        == netwatch::SocketEventType::StateChanged);

    REQUIRE(events.front().previous_state.has_value());
    CHECK(*events.front().previous_state
        == netwatch::SocketState::SynSent);

    CHECK(events.front().observation.socket.state
        == netwatch::SocketState::Established);
}

TEST_CASE("One diff can report opened and closed sockets")
{
    const auto closedSocket = makeSocket(500U, 5000U);
    const auto retainedSocket = makeSocket(600U, 6000U);
    const auto openedSocket = makeSocket(700U, 7000U);

    netwatch::SnapshotDiffer differ;

    const auto events = differ.diff(
        snapshotOf({closedSocket, retainedSocket}),
        snapshotOf({retainedSocket, openedSocket}),
        std::chrono::system_clock::time_point {}
    );

    REQUIRE(events.size() == 2U);
    CHECK(events[0].type
        == netwatch::SocketEventType::Opened);
    CHECK(events[0].observation.socket.inode == 700U);

    CHECK(events[1].type
        == netwatch::SocketEventType::Closed);
    CHECK(events[1].observation.socket.inode == 500U);
}
