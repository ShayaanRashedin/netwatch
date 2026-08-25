#pragma once

#include "netwatch/core/ProcessInfo.hpp"

#include <cstdint>
#include <filesystem>
#include <unordered_map>
#include <vector>

namespace netwatch {

class ProcessResolver {
public:
    using SocketOwnerMap =
        std::unordered_map<
            std::uint64_t,
            std::vector<ProcessInfo>
        >;

    explicit ProcessResolver(
        std::filesystem::path procRoot = "/proc"
    );

    [[nodiscard]]
    SocketOwnerMap resolveSocketOwners() const;

private:
    std::filesystem::path proc_root_;
};

} // namespace netwatch