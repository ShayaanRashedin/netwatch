#include "netwatch/persistence/EventWriter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>

namespace {

class WriterDatabase {
public:
    WriterDatabase()
    {
        static std::atomic_uint64_t sequence {};

        path_ = std::filesystem::temp_directory_path()
            / ("netwatch-writer-test-"
                + std::to_string(++sequence)
                + "-"
                + std::to_string(
                    std::chrono::steady_clock::now()
                        .time_since_epoch()
                        .count()
                )
                + ".db");
    }

    ~WriterDatabase()
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

netwatch::SocketEvent writerEvent(const std::uint64_t inode)
{
    netwatch::SocketEvent event;
    event.type = netwatch::SocketEventType::Opened;
    event.observed_at = std::chrono::system_clock::now();

    auto& socket = event.observation.socket;
    socket.family = netwatch::IpFamily::IPv4;
    socket.protocol = netwatch::TransportProtocol::Tcp;
    socket.local = {"127.0.0.1", 8080U};
    socket.remote = {"0.0.0.0", 0U};
    socket.state = netwatch::SocketState::Listen;
    socket.inode = inode;

    return event;
}

} // namespace

TEST_CASE("Event writer drains its bounded queue before shutdown")
{
    WriterDatabase database;
    std::size_t persistedCount {};

    {
        netwatch::EventWriter writer {database.path(), 1U};

        REQUIRE(writer.submit(writerEvent(1U)));
        REQUIRE(writer.submit(writerEvent(2U)));
        REQUIRE(writer.submit(writerEvent(3U)));

        writer.stop();

        CHECK_FALSE(writer.failure().has_value());
        persistedCount = writer.persistedCount();
    }

    CHECK(persistedCount == 3U);

    netwatch::SQLiteEventRepository repository {database.path()};
    CHECK(repository.eventCount() == 3U);
}

TEST_CASE("Event writer rejects submissions after it stops")
{
    WriterDatabase database;
    netwatch::EventWriter writer {database.path(), 2U};

    writer.stop();

    CHECK_FALSE(writer.submit(writerEvent(1U)));
    CHECK(writer.persistedCount() == 0U);
    CHECK_FALSE(writer.failure().has_value());
}

