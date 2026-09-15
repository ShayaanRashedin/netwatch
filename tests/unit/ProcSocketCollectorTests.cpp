#include "netwatch/procfs/ProcSocketCollector.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace {

class TemporaryProcNetTree {
public:
    TemporaryProcNetTree()
        : root_ {
            std::filesystem::temp_directory_path()
            / (
                "netwatch-socket-collector-"
                + std::to_string(static_cast<long long>(::getpid()))
            )
        }
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_);
    }

    ~TemporaryProcNetTree()
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]]
    const std::filesystem::path& root() const
    {
        return root_;
    }

private:
    std::filesystem::path root_;
};

void writeTable(
    const std::filesystem::path& path,
    const std::string_view row)
{
    std::ofstream output {path};

    REQUIRE(output.is_open());

    output
        << "header\n"
        << row
        << '\n';
}

} // namespace

TEST_CASE("Collector combines all four procfs socket tables")
{
    TemporaryProcNetTree procNet;

    writeTable(
        procNet.root() / "tcp",
        "0: 0100007F:1F90 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 111"
    );

    writeTable(
        procNet.root() / "tcp6",
        "0: 00000000000000000000000001000000:01BB "
        "00000000000000000000000000000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 222"
    );

    writeTable(
        procNet.root() / "udp",
        "0: 00000000:14E9 00000000:0000 07 "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 333"
    );

    writeTable(
        procNet.root() / "udp6",
        "0: 00000000000000000000000000000000:0035 "
        "00000000000000000000000000000000:0000 07 "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 444"
    );

    netwatch::ProcSocketCollector collector {procNet.root()};

    const auto sockets = collector.collect();

    REQUIRE(sockets.size() == 4U);

    CHECK(sockets[0].family == netwatch::IpFamily::IPv4);
    CHECK(sockets[0].protocol == netwatch::TransportProtocol::Tcp);
    CHECK(sockets[0].inode == 111U);

    CHECK(sockets[1].family == netwatch::IpFamily::IPv6);
    CHECK(sockets[1].protocol == netwatch::TransportProtocol::Tcp);
    CHECK(sockets[1].inode == 222U);

    CHECK(sockets[2].family == netwatch::IpFamily::IPv4);
    CHECK(sockets[2].protocol == netwatch::TransportProtocol::Udp);
    CHECK(sockets[2].inode == 333U);

    CHECK(sockets[3].family == netwatch::IpFamily::IPv6);
    CHECK(sockets[3].protocol == netwatch::TransportProtocol::Udp);
    CHECK(sockets[3].inode == 444U);
}

TEST_CASE("Collector tolerates missing procfs socket tables")
{
    TemporaryProcNetTree procNet;

    writeTable(
        procNet.root() / "tcp",
        "0: 0100007F:0016 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 "
        "1000 0 555"
    );

    netwatch::ProcSocketCollector collector {procNet.root()};

    const auto sockets = collector.collect();

    REQUIRE(sockets.size() == 1U);
    CHECK(sockets.front().inode == 555U);
}
