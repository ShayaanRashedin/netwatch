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

enum class TcpState {
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

    TcpState state {TcpState::Unknown};

    std::uint64_t inode {};
    std::uint64_t tx_queue_bytes {};
    std::uint64_t rx_queue_bytes {};
};

}