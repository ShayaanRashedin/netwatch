#pragma once

#include <cstdint>
#include <string>

namespace netwatch {

enum class IpFamily {
    IPv4,
    IPv6
};

enum class TransportProtocol {
    Tcp,
    Udp
};

enum class SocketState {
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynReceived,
    Unconnected,
    Unknown
};

struct Endpoint {
    std::string address;
    std::uint16_t port {};
};

struct SocketRecord {
    IpFamily family {};
    TransportProtocol protocol {};

    Endpoint local;
    Endpoint remote;

    SocketState state {SocketState::Unknown};

    std::uint64_t inode {};
    std::uint64_t tx_queue_bytes {};
    std::uint64_t rx_queue_bytes {};
};

} // namespace netwatch
