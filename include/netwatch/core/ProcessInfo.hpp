#pragma once

#include <cstdint>
#include <string>

namespace netwatch {

struct ProcessInfo {
    int pid {};
    std::uint64_t start_time_ticks {};
    unsigned int uid {};

    std::string username;
    std::string name;
    std::string executable;
    std::string command_line;
};

} // namespace netwatch