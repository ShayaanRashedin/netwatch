#include "netwatch/storage/SQLiteEventRepository.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>

namespace {

class TemporaryDatabase {
public:
    TemporaryDatabase()
    {
        static std::atomic_uint64_t sequence {};

        path_ = std::filesystem::temp_directory_path()
            / ("netwatch-repository-test-"
                + std::to_string(++sequence)
                + "-"
                + std::to_string(
                    std::chrono::steady_clock::now()
                        .time_since_epoch()
                        .count()
                )
                + ".db");
    }

    ~TemporaryDatabase()
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

netwatch::SocketEvent makeEvent(
    const std::int64_t observedSeconds,
    const std::uint64_t inode,
    const netwatch::SocketEventType type =
        netwatch::SocketEventType::Opened)
{
    netwatch::SocketEvent event;
    event.type = type;
    event.observed_at = std::chrono::system_clock::time_point {
        std::chrono::seconds {observedSeconds}
    };

    auto& socket = event.observation.socket;
    socket.family = netwatch::IpFamily::IPv6;
    socket.protocol = netwatch::TransportProtocol::Tcp;
    socket.local = {"::1", 8080U};
    socket.remote = {"::", 0U};
    socket.state = netwatch::SocketState::Listen;
    socket.inode = inode;
    socket.tx_queue_bytes = 12U;
    socket.rx_queue_bytes = 34U;

    return event;
}

} // namespace

TEST_CASE("SQLite repository round-trips event and process metadata")
{
    TemporaryDatabase database;
    netwatch::SQLiteEventRepository repository {database.path()};

    auto event = makeEvent(
        42,
        9001U,
        netwatch::SocketEventType::StateChanged
    );
    event.previous_state = netwatch::SocketState::SynReceived;

    netwatch::ProcessInfo firstOwner;
    firstOwner.pid = 101;
    firstOwner.start_time_ticks = 500U;
    firstOwner.uid = 1000U;
    firstOwner.username = "alice";
    firstOwner.name = "server";
    firstOwner.executable = "/usr/bin/server";
    firstOwner.command_line = "server --listen";

    netwatch::ProcessInfo secondOwner;
    secondOwner.pid = 202;
    secondOwner.name = "helper";

    event.observation.owners = {firstOwner, secondOwner};
    repository.persist(event);

    CHECK(repository.eventCount() == 1U);
    CHECK(repository.processCount() == 2U);

    const auto stored = repository.recentEvents(10U);
    REQUIRE(stored.size() == 1U);

    const auto& restored = stored.front().event;
    CHECK(restored.type == netwatch::SocketEventType::StateChanged);
    REQUIRE(restored.previous_state.has_value());
    CHECK(*restored.previous_state
        == netwatch::SocketState::SynReceived);
    CHECK(restored.observation.socket.family
        == netwatch::IpFamily::IPv6);
    CHECK(restored.observation.socket.inode == 9001U);
    CHECK(restored.observed_at == event.observed_at);

    REQUIRE(restored.observation.owners.size() == 2U);
    CHECK(restored.observation.owners[0].pid == 101);
    CHECK(restored.observation.owners[0].uid == 1000U);
    CHECK(restored.observation.owners[0].command_line
        == "server --listen");
    CHECK(restored.observation.owners[1].pid == 202);
}

TEST_CASE("SQLite recent event query is newest-first and bounded")
{
    TemporaryDatabase database;
    netwatch::SQLiteEventRepository repository {database.path()};

    repository.persist(makeEvent(10, 10U));
    repository.persist(makeEvent(30, 30U));
    repository.persist(makeEvent(20, 20U));

    const auto recent = repository.recentEvents(2U);

    REQUIRE(recent.size() == 2U);
    CHECK(recent[0].event.observation.socket.inode == 30U);
    CHECK(recent[1].event.observation.socket.inode == 20U);
    CHECK(repository.recentEvents(0U).empty());
}

TEST_CASE("SQLite retention removes old events and related processes")
{
    TemporaryDatabase database;
    netwatch::SQLiteEventRepository repository {database.path()};

    auto oldEvent = makeEvent(10, 10U);
    netwatch::ProcessInfo owner;
    owner.pid = 55;
    owner.name = "old-process";
    oldEvent.observation.owners.push_back(owner);

    repository.persist(oldEvent);
    repository.persist(makeEvent(20, 20U));

    const auto deleted = repository.deleteEventsOlderThan(
        std::chrono::system_clock::time_point {
            std::chrono::seconds {15}
        }
    );

    CHECK(deleted == 1U);
    CHECK(repository.eventCount() == 1U);
    CHECK(repository.processCount() == 0U);
    REQUIRE(repository.recentEvents(1U).size() == 1U);
    CHECK(repository.recentEvents(1U)[0]
        .event.observation.socket.inode == 20U);
}

