#include "netwatch/procfs/ProcNetSocketParser.hpp"

#include <fstream>
#include <iostream>
#include <string_view>

namespace {

std::string_view tcpStateToString(
    const netwatch::TcpState state)
{
    using netwatch::TcpState;

    switch (state) {
    case TcpState::Established:
        return "ESTABLISHED";

    case TcpState::SynSent:
        return "SYN_SENT";

    case TcpState::SynReceived:
        return "SYN_RECV";

    case TcpState::FinWait1:
        return "FIN_WAIT1";

    case TcpState::FinWait2:
        return "FIN_WAIT2";

    case TcpState::TimeWait:
        return "TIME_WAIT";

    case TcpState::Closed:
        return "CLOSED";

    case TcpState::CloseWait:
        return "CLOSE_WAIT";

    case TcpState::LastAck:
        return "LAST_ACK";

    case TcpState::Listen:
        return "LISTEN";

    case TcpState::Closing:
        return "CLOSING";

    case TcpState::Unknown:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}

} // namespace

int main()
{
    std::ifstream tcpFile {"/proc/net/tcp"};

    if (!tcpFile.is_open()) {
        std::cerr
            << "Failed to open /proc/net/tcp\n";

        return 1;
    }

    netwatch::ProcNetSocketParser parser;

    const auto sockets = parser.parse(
        tcpFile,
        netwatch::IpFamily::IPv4,
        netwatch::TransportProtocol::Tcp
    );

    std::cout
        << "NetWatch IPv4 TCP snapshot\n"
        << "Sockets found: "
        << sockets.size()
        << "\n\n";

    for (const auto& socket : sockets) {
        std::cout
            << "TCP "
            << socket.local.address
            << ':'
            << socket.local.port
            << " -> "
            << socket.remote.address
            << ':'
            << socket.remote.port
            << "  "
            << tcpStateToString(socket.state)
            << "  inode="
            << socket.inode
            << '\n';
    }

    return 0;
}