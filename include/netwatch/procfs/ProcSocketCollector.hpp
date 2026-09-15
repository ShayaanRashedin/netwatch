#pragma once

#include "netwatch/core/NetworkTypes.hpp"

#include <filesystem>
#include <vector>

namespace netwatch {

class ProcSocketCollector {
public:
    explicit ProcSocketCollector(
        std::filesystem::path procNetRoot = "/proc/net"
    );

    [[nodiscard]]
    std::vector<SocketRecord> collect() const;

private:
    std::filesystem::path proc_net_root_;
};

} // namespace netwatch
