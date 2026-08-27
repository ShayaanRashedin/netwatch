#include "netwatch/procfs/ProcessResolver.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace {

class TemporaryProcTree {
public:
    TemporaryProcTree()
        : root_ {
            std::filesystem::temp_directory_path()
            / (
                "netwatch-process-resolver-"
                + std::to_string(static_cast<long long>(::getpid()))
            )
        }
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
        std::filesystem::create_directories(root_);
    }

    ~TemporaryProcTree()
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

void writeFile(
    const std::filesystem::path& path,
    const std::string_view content)
{
    std::ofstream output {path};

    REQUIRE(output.is_open());
    output << content;
}

std::filesystem::path createProcess(
    const std::filesystem::path& root,
    const int pid,
    const std::string_view name)
{
    const auto processDirectory =
        root / std::to_string(pid);

    std::filesystem::create_directories(
        processDirectory / "fd"
    );

    writeFile(
        processDirectory / "comm",
        std::string {name} + '\n'
    );

    return processDirectory;
}

void createSocketLink(
    const std::filesystem::path& processDirectory,
    const std::string_view fileDescriptor,
    const std::uint64_t inode)
{
    std::filesystem::create_symlink(
        "socket:[" + std::to_string(inode) + ']',
        processDirectory / "fd" / std::string {fileDescriptor}
    );
}

} // namespace

TEST_CASE("Socket inode is correlated with complete process metadata")
{
    TemporaryProcTree procTree;

    const auto processDirectory =
        createProcess(procTree.root(), 4242, "python3");

    const auto currentUid =
        static_cast<unsigned int>(::getuid());

    {
        std::ofstream statusFile {
            processDirectory / "status"
        };

        REQUIRE(statusFile.is_open());

        statusFile
            << "Name:\tpython3\n"
            << "Uid:\t"
            << currentUid << '\t'
            << currentUid << '\t'
            << currentUid << '\t'
            << currentUid << '\n';
    }

    createSocketLink(processDirectory, "3", 32808U);

    std::filesystem::create_symlink(
        "/tmp/not-a-socket",
        processDirectory / "fd" / "4"
    );

    std::filesystem::create_symlink(
        "/usr/bin/python3",
        processDirectory / "exe"
    );

    {
        std::ofstream commandLineFile {
            processDirectory / "cmdline",
            std::ios::binary
        };

        REQUIRE(commandLineFile.is_open());

        commandLineFile << "python3";
        commandLineFile.put('\0');
        commandLineFile << "-m";
        commandLineFile.put('\0');
        commandLineFile << "http.server";
        commandLineFile.put('\0');
        commandLineFile << "8080";
        commandLineFile.put('\0');
    }

    writeFile(
        processDirectory / "stat",
        "4242 (python worker) S "
        "1 2 3 4 5 6 7 8 9 "
        "10 11 12 13 14 15 16 17 18 "
        "987654 0\n"
    );

    netwatch::ProcessResolver resolver {procTree.root()};

    const auto owners = resolver.resolveSocketOwners();

    REQUIRE(owners.contains(32808U));
    REQUIRE(owners.at(32808U).size() == 1U);

    const auto& process = owners.at(32808U).front();

    CHECK(process.pid == 4242);
    CHECK(process.name == "python3");

    REQUIRE(process.uid.has_value());
    CHECK(*process.uid == currentUid);
    CHECK_FALSE(process.username.empty());

    CHECK(process.executable == "/usr/bin/python3");
    CHECK(process.command_line == "python3 -m http.server 8080");

    REQUIRE(process.start_time_ticks.has_value());
    CHECK(*process.start_time_ticks == 987654U);
}

TEST_CASE("Duplicate file descriptors produce one owner record")
{
    TemporaryProcTree procTree;

    const auto processDirectory =
        createProcess(procTree.root(), 101, "worker");

    createSocketLink(processDirectory, "3", 700U);
    createSocketLink(processDirectory, "4", 700U);

    netwatch::ProcessResolver resolver {procTree.root()};
    const auto owners = resolver.resolveSocketOwners();

    REQUIRE(owners.contains(700U));
    REQUIRE(owners.at(700U).size() == 1U);
    CHECK(owners.at(700U).front().pid == 101);
}

TEST_CASE("Shared socket inode retains every owning process")
{
    TemporaryProcTree procTree;

    const auto firstProcess =
        createProcess(procTree.root(), 101, "first");

    const auto secondProcess =
        createProcess(procTree.root(), 202, "second");

    createSocketLink(firstProcess, "3", 900U);
    createSocketLink(secondProcess, "7", 900U);

    netwatch::ProcessResolver resolver {procTree.root()};
    const auto owners = resolver.resolveSocketOwners();

    REQUIRE(owners.contains(900U));
    REQUIRE(owners.at(900U).size() == 2U);

    std::set<int> pids;

    for (const auto& process : owners.at(900U)) {
        pids.insert(process.pid);
    }

    CHECK(pids == std::set<int> {101, 202});
}

TEST_CASE("Malformed procfs entries are ignored")
{
    TemporaryProcTree procTree;

    std::filesystem::create_directories(
        procTree.root() / "self"
    );

    const auto malformedProcess =
        createProcess(procTree.root(), 303, "malformed");

    std::filesystem::create_symlink(
        "socket:[not-a-number]",
        malformedProcess / "fd" / "3"
    );

    std::filesystem::create_symlink(
        "/tmp/ordinary-file",
        malformedProcess / "fd" / "4"
    );

    const auto missingNameProcess =
        procTree.root() / "404";

    std::filesystem::create_directories(
        missingNameProcess / "fd"
    );

    createSocketLink(missingNameProcess, "5", 123U);

    netwatch::ProcessResolver resolver {procTree.root()};
    const auto owners = resolver.resolveSocketOwners();

    CHECK(owners.empty());
}

TEST_CASE("Missing optional metadata does not hide a socket owner")
{
    TemporaryProcTree procTree;

    const auto processDirectory =
        createProcess(procTree.root(), 505, "minimal");

    createSocketLink(processDirectory, "8", 321U);

    netwatch::ProcessResolver resolver {procTree.root()};
    const auto owners = resolver.resolveSocketOwners();

    REQUIRE(owners.contains(321U));
    REQUIRE(owners.at(321U).size() == 1U);

    const auto& process = owners.at(321U).front();

    CHECK(process.pid == 505);
    CHECK(process.name == "minimal");
    CHECK_FALSE(process.uid.has_value());
    CHECK(process.username.empty());
    CHECK(process.executable.empty());
    CHECK(process.command_line.empty());
    CHECK_FALSE(process.start_time_ticks.has_value());
}
