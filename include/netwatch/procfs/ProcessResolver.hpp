#pragma once

#include "netwatch/core/ProcessInfo.hpp"

#include <filesystem>

namespace netwatch {

class ProcessResolver {
public:
    using SocketOwnerMap = netwatch::SocketOwnerMap;

    explicit ProcessResolver(
        std::filesystem::path procRoot = "/proc"
    );

    [[nodiscard]]
    SocketOwnerMap resolveSocketOwners() const;

private:
    std::filesystem::path proc_root_;
};

} // namespace netwatch
