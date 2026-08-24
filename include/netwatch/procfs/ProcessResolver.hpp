#pragma once

#include "netwatch/core/ProcessInfo.hpp"

#include <cstdint>
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

    [[nodiscard]]
    SocketOwnerMap resolveSocketOwners() const;
};

} // namespace netwatch