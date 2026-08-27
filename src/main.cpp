#include "netwatch/core/NetworkTypes.hpp"
#include "netwatch/core/ProcessInfo.hpp"
#include "netwatch/procfs/ProcessResolver.hpp"
#include "netwatch/procfs/ProcSocketCollector.hpp"

#include <iostream>
#include <string_view>

namespace {

std::string_view familyToString(
    const netwatch::IpFamily family)
{
    switch (family) {
    case netwatch::IpFamily::IPv4:
        return "IPv4";

    case netwatch::IpFamily::IPv6:
        return "IPv6";
    }

    return "UNKNOWN";
}

std::string_view protocolToString(
    const netwatch::TransportProtocol protocol)
{
    switch (protocol) {
    case netwatch::TransportProtocol::Tcp:
        return "TCP";

    case netwatch::TransportProtocol::Udp:
        return "UDP";
    }

    return "UNKNOWN";
}

std::string_view socketStateToString(
    const netwatch::SocketState state)
{
    using netwatch::SocketState;

    switch (state) {
    case SocketState::Established:
        return "ESTABLISHED";

    case SocketState::SynSent:
        return "SYN_SENT";

    case SocketState::SynReceived:
        return "SYN_RECV";

    case SocketState::FinWait1:
        return "FIN_WAIT1";

    case SocketState::FinWait2:
        return "FIN_WAIT2";

    case SocketState::TimeWait:
        return "TIME_WAIT";

    case SocketState::Closed:
        return "CLOSED";

    case SocketState::CloseWait:
        return "CLOSE_WAIT";

    case SocketState::LastAck:
        return "LAST_ACK";

    case SocketState::Listen:
        return "LISTEN";

    case SocketState::Closing:
        return "CLOSING";

    case SocketState::NewSynReceived:
        return "NEW_SYN_RECV";

    case SocketState::Unconnected:
        return "UNCONN";

    case SocketState::Unknown:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}

void printEndpoint(
    const netwatch::Endpoint& endpoint,
    const netwatch::IpFamily family)
{
    if (family == netwatch::IpFamily::IPv6) {
        std::cout
            << '['
            << endpoint.address
            << "]:"
            << endpoint.port;

        return;
    }

    std::cout
        << endpoint.address
        << ':'
        << endpoint.port;
}

void printProcess(const netwatch::ProcessInfo& process)
{
    std::cout
        << " owner={pid="
        << process.pid
        << " process="
        << process.name;

    if (process.uid.has_value()) {
        std::cout
            << " uid="
            << *process.uid;
    }

    if (!process.username.empty()) {
        std::cout
            << " user="
            << process.username;
    }

    if (!process.executable.empty()) {
        std::cout
            << " exe="
            << process.executable;
    }

    if (!process.command_line.empty()) {
        std::cout
            << " cmd=\""
            << process.command_line
            << '"';
    }

    if (process.start_time_ticks.has_value()) {
        std::cout
            << " start_ticks="
            << *process.start_time_ticks;
    }

    std::cout << '}';
}

} // namespace

int main()
{
    netwatch::ProcSocketCollector collector;
    const auto sockets = collector.collect();

    netwatch::ProcessResolver processResolver;
    const auto socketOwners =
        processResolver.resolveSocketOwners();

    std::cout
        << "NetWatch socket snapshot\n"
        << "Sockets found: "
        << sockets.size()
        << "\n\n";

    for (const auto& socket : sockets) {
        std::cout
            << protocolToString(socket.protocol)
            << ' '
            << familyToString(socket.family)
            << ' ';

        printEndpoint(socket.local, socket.family);
        std::cout << " -> ";
        printEndpoint(socket.remote, socket.family);

        std::cout
            << ' '
            << socketStateToString(socket.state)
            << " inode="
            << socket.inode
            << " tx="
            << socket.tx_queue_bytes
            << " rx="
            << socket.rx_queue_bytes;

        const auto owners = socketOwners.find(socket.inode);

        if (owners == socketOwners.end()) {
            std::cout << " owner=unknown";
        } else {
            for (const auto& process : owners->second) {
                printProcess(process);
            }
        }

        std::cout << '\n';
    }

    return 0;
}
