#pragma once

#include "netwatch/core/NetworkTypes.hpp"
#include "netwatch/core/ProcessInfo.hpp"

#include <compare>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace netwatch {

struct SocketKey {
    IpFamily family {};
    TransportProtocol protocol {};

    std::string local_address;
    std::uint16_t local_port {};

    std::string remote_address;
    std::uint16_t remote_port {};

    std::uint64_t inode {};

    auto operator<=>(const SocketKey&) const = default;
};

struct ObservedSocket {
    SocketRecord socket;
    std::vector<ProcessInfo> owners;
};

using SocketSnapshot =
    std::map<SocketKey, ObservedSocket>;

[[nodiscard]]
SocketKey makeSocketKey(const SocketRecord& socket);

[[nodiscard]]
SocketSnapshot makeSocketSnapshot(
    const std::vector<SocketRecord>& sockets,
    const SocketOwnerMap& owners
);

} // namespace netwatch
