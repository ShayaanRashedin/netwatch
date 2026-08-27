#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace netwatch {

struct ProcessInfo {
    int pid {};
    std::optional<std::uint64_t> start_time_ticks;
    std::optional<unsigned int> uid;

    std::string username;
    std::string name;
    std::string executable;
    std::string command_line;
};

} // namespace netwatch
