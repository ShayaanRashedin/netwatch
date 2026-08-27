#include "netwatch/procfs/ProcessResolver.hpp"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <pwd.h>
#include <unistd.h>
#include <vector>
#include <iterator>
#include <sstream>

namespace netwatch {

namespace {

std::optional<unsigned int> readProcessUid(
    const std::filesystem::path& processDirectory)
{
    std::ifstream input {processDirectory / "status"};
    std::string line;

    constexpr std::string_view prefix {"Uid:"};

    while (std::getline(input, line)) {
        if (!line.starts_with(prefix)) {
            continue;
        }

        std::string_view value {line};
        value.remove_prefix(prefix.size());

        const auto firstDigit =
            value.find_first_not_of(" \t");

        if (firstDigit == std::string_view::npos) {
            return std::nullopt;
        }

        value.remove_prefix(firstDigit);

        const auto separator =
            value.find_first_of(" \t");

        if (separator != std::string_view::npos) {
            value = value.substr(0, separator);
        }

        unsigned int uid {};

        const auto [ptr, error] = std::from_chars(
            value.data(),
            value.data() + value.size(),
            uid
        );

        if (error != std::errc {}
            || ptr != value.data() + value.size()) {
            return std::nullopt;
        }

        return uid;
    }

    return std::nullopt;
}

std::string lookupUsername(const unsigned int uid)
{
    const long configuredSize =
        ::sysconf(_SC_GETPW_R_SIZE_MAX);

    const std::size_t bufferSize =
        configuredSize > 0
            ? static_cast<std::size_t>(configuredSize)
            : std::size_t {16'384};

    std::vector<char> buffer(bufferSize);

    struct passwd entry {};
    struct passwd* result = nullptr;

    const int status = ::getpwuid_r(
        static_cast<uid_t>(uid),
        &entry,
        buffer.data(),
        buffer.size(),
        &result
    );

    if (status != 0
        || result == nullptr
        || entry.pw_name == nullptr) {
        return {};
    }

    return entry.pw_name;
}

std::optional<int> parsePid(const std::string_view text)
{
    int pid {};

    const auto [ptr, error] = std::from_chars(
        text.data(),
        text.data() + text.size(),
        pid
    );

    if (error != std::errc {}
        || ptr != text.data() + text.size()
        || pid <= 0) {
        return std::nullopt;
    }

    return pid;
}

std::optional<std::uint64_t> parseSocketInode(
    const std::filesystem::path& target)
{
    const std::string text = target.string();
    constexpr std::string_view prefix {"socket:["};

    if (!text.starts_with(prefix)
        || text.size() <= prefix.size()
        || text.back() != ']') {
        return std::nullopt;
    }

    const std::string_view inodeText {
        text.data() + prefix.size(),
        text.size() - prefix.size() - 1U
    };

    std::uint64_t inode {};

    const auto [ptr, error] = std::from_chars(
        inodeText.data(),
        inodeText.data() + inodeText.size(),
        inode
    );

    if (error != std::errc {}
        || ptr != inodeText.data() + inodeText.size()) {
        return std::nullopt;
    }

    return inode;
}

std::optional<std::string> readProcessName(
    const std::filesystem::path& processDirectory)
{
    std::ifstream input {processDirectory / "comm"};
    std::string name;

    if (!std::getline(input, name)) {
        return std::nullopt;
    }

    return name;
}

std::string readProcessExecutable(
    const std::filesystem::path& processDirectory)
{
    std::error_code error;

    const auto executable = std::filesystem::read_symlink(
        processDirectory / "exe",
        error
    );

    if (error) {
        return {};
    }

    return executable.string();
}

std::string readProcessCommandLine(
    const std::filesystem::path& processDirectory)
{
    std::ifstream input {
        processDirectory / "cmdline",
        std::ios::binary
    };

    if (!input.is_open()) {
        return {};
    }

    std::string commandLine {
        std::istreambuf_iterator<char> {input},
        std::istreambuf_iterator<char> {}
    };

    for (char& character : commandLine) {
        if (character == '\0') {
            character = ' ';
        }
    }

    while (!commandLine.empty()
           && commandLine.back() == ' ') {
        commandLine.pop_back();
    }

    return commandLine;
}

std::optional<std::uint64_t> readProcessStartTimeTicks(
    const std::filesystem::path& processDirectory)
{
    std::ifstream input {
        processDirectory / "stat"
    };

    std::string line;

    if (!std::getline(input, line)) {
        return std::nullopt;
    }

    // The process name is enclosed in parentheses and may contain spaces.
    const auto closingParenthesis = line.rfind(')');

    if (closingParenthesis == std::string::npos
        || closingParenthesis + 2U >= line.size()) {
        return std::nullopt;
    }

    std::istringstream fields {
        line.substr(closingParenthesis + 2U)
    };

    std::string field;

    // The stream begins at field 3. Start time is field 22.
    for (int fieldNumber = 3;
         fieldNumber <= 22;
         ++fieldNumber) {
        if (!(fields >> field)) {
            return std::nullopt;
        }

        if (fieldNumber != 22) {
            continue;
        }

        std::uint64_t startTimeTicks {};

        const auto [ptr, error] = std::from_chars(
            field.data(),
            field.data() + field.size(),
            startTimeTicks
        );

        if (error != std::errc {}
            || ptr != field.data() + field.size()) {
            return std::nullopt;
        }

        return startTimeTicks;
    }

    return std::nullopt;
    
}

} // namespace

ProcessResolver::ProcessResolver(
    std::filesystem::path procRoot)
    : proc_root_ {std::move(procRoot)}
{
}

ProcessResolver::SocketOwnerMap
ProcessResolver::resolveSocketOwners() const
{
    SocketOwnerMap owners;

    const auto options =
        std::filesystem::directory_options::skip_permission_denied;

    std::error_code processError;

    std::filesystem::directory_iterator processIterator {
        proc_root_,
        options,
        processError
    };

    const std::filesystem::directory_iterator end;

    while (processIterator != end) {
        const auto processDirectory = processIterator->path();

        processIterator.increment(processError);
        processError.clear();

        const auto pid =
            parsePid(processDirectory.filename().string());

        if (!pid.has_value()) {
            continue;
        }

        const auto name = readProcessName(processDirectory);

        if (!name.has_value()) {
            continue;
        }

        ProcessInfo process;
        process.pid = *pid;
        process.name = *name;

        const auto uid = readProcessUid(processDirectory);

        if (uid.has_value()) {
            process.uid = *uid;
            process.username = lookupUsername(*uid);
        }

        process.executable =
            readProcessExecutable(processDirectory);

        process.command_line =
            readProcessCommandLine(processDirectory);

        const auto startTimeTicks =
            readProcessStartTimeTicks(processDirectory);

        if (startTimeTicks.has_value()) {
            process.start_time_ticks =
                *startTimeTicks;
        }
        
        std::error_code fdError;

        std::filesystem::directory_iterator fdIterator {
            processDirectory / "fd",
            options,
            fdError
        };

        if (fdError) {
            continue;
        }

        std::unordered_set<std::uint64_t> seenInodes;

        while (fdIterator != end) {
            const auto fdPath = fdIterator->path();

            fdIterator.increment(fdError);
            fdError.clear();

            std::error_code linkError;
            const auto target =
                std::filesystem::read_symlink(fdPath, linkError);

            if (linkError) {
                continue;
            }

            const auto inode = parseSocketInode(target);

            if (!inode.has_value()) {
                continue;
            }

            if (!seenInodes.insert(*inode).second) {
                continue;
            }

            owners[*inode].push_back(process);
        }
    }

    return owners;
}

} // namespace netwatch