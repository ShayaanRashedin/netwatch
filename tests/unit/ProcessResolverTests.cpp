#include "netwatch/procfs/ProcessResolver.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
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

} // namespace

TEST_CASE("Socket inode is correlated with its owning process")
{
    TemporaryProcTree procTree;

    const auto processDirectory =
        procTree.root() / "4242";

    std::filesystem::create_directories(
        processDirectory / "fd"
    );

    {
        std::ofstream commFile {
            processDirectory / "comm"
        };

        REQUIRE(commFile.is_open());
        commFile << "python3\n";
    }

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

    std::filesystem::create_symlink(
        "socket:[32808]",
        processDirectory / "fd" / "3"
    );

    std::filesystem::create_symlink(
        "/tmp/not-a-socket",
        processDirectory / "fd" / "4"
    );

    netwatch::ProcessResolver resolver {
        procTree.root()
    };

    const auto owners =
        resolver.resolveSocketOwners();

    REQUIRE(owners.contains(32808));
    REQUIRE(owners.at(32808).size() == 1);

    const auto& process =
        owners.at(32808).front();

    CHECK(process.pid == 4242);
    CHECK(process.name == "python3");
    CHECK(owners.size() == 1);
    CHECK(process.uid == currentUid);
    CHECK_FALSE(process.username.empty());
}