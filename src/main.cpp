#include "netwatch/core/NetworkTypes.hpp"
#include "netwatch/core/ProcessInfo.hpp"
#include "netwatch/core/SocketSnapshot.hpp"
#include "netwatch/monitoring/SnapshotDiffer.hpp"
#include "netwatch/procfs/ProcessResolver.hpp"
#include "netwatch/procfs/ProcSocketCollector.hpp"

#include <charconv>
#include <chrono>
#include <csignal>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace {

volatile std::sig_atomic_t stopRequested = 0;

void handleStopSignal(const int)
{
    stopRequested = 1;
}

struct Options {
    std::chrono::milliseconds interval {1000};
    bool once {};
    bool help {};
};

Options parseOptions(const int argc, char* argv[])
{
    Options options;

    for (int argumentIndex = 1;
         argumentIndex < argc;
         ++argumentIndex) {
        const std::string_view argument {
            argv[argumentIndex]
        };

        if (argument == "--once") {
            options.once = true;
            continue;
        }

        if (argument == "--help" || argument == "-h") {
            options.help = true;
            continue;
        }

        if (argument == "--interval-ms") {
            if (argumentIndex + 1 >= argc) {
                throw std::invalid_argument {
                    "--interval-ms requires a value"
                };
            }

            ++argumentIndex;

            const std::string_view valueText {
                argv[argumentIndex]
            };

            std::chrono::milliseconds::rep value {};

            const auto [ptr, error] = std::from_chars(
                valueText.data(),
                valueText.data() + valueText.size(),
                value
            );

            if (error != std::errc {}
                || ptr != valueText.data() + valueText.size()
                || value < 50
                || value > 3'600'000) {
                throw std::invalid_argument {
                    "--interval-ms must be between 50 and 3600000"
                };
            }

            options.interval =
                std::chrono::milliseconds {value};

            continue;
        }

        throw std::invalid_argument {
            "unknown option: " + std::string {argument}
        };
    }

    return options;
}

void printUsage()
{
    std::cout
        << "Usage: netwatch [--once] [--interval-ms VALUE]\n"
        << "\n"
        << "  --once               Print one snapshot and exit\n"
        << "  --interval-ms VALUE  Poll every 50-3600000 ms"
        << " (default: 1000)\n"
        << "  --help, -h           Show this help\n";
}

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

std::string eventTypeToString(
    const netwatch::SocketEvent& event)
{
    switch (event.type) {
    case netwatch::SocketEventType::Opened:
        return "OPENED";

    case netwatch::SocketEventType::Closed:
        return "CLOSED";

    case netwatch::SocketEventType::StateChanged:
        if (event.previous_state.has_value()) {
            return "STATE_CHANGED "
                + std::string {
                    socketStateToString(*event.previous_state)
                }
                + "->"
                + std::string {
                    socketStateToString(
                        event.observation.socket.state
                    )
                };
        }

        return "STATE_CHANGED";
    }

    return "UNKNOWN";
}

std::string formatTimestamp(
    const std::chrono::system_clock::time_point timePoint)
{
    const std::time_t rawTime =
        std::chrono::system_clock::to_time_t(timePoint);

    std::tm utcTime {};

    if (::gmtime_r(&rawTime, &utcTime) == nullptr) {
        return "unknown-time";
    }

    std::ostringstream output;
    output << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");

    return output.str();
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

void printObservation(
    const netwatch::ObservedSocket& observation)
{
    const auto& socket = observation.socket;

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

    if (observation.owners.empty()) {
        std::cout << " owner=unknown";
    } else {
        for (const auto& process : observation.owners) {
            printProcess(process);
        }
    }
}

void printSnapshot(const netwatch::SocketSnapshot& snapshot)
{
    std::cout
        << "NetWatch socket snapshot\n"
        << "Sockets found: "
        << snapshot.size()
        << "\n\n";

    for (const auto& [key, observation] : snapshot) {
        static_cast<void>(key);
        printObservation(observation);
        std::cout << '\n';
    }
}

void printEvent(const netwatch::SocketEvent& event)
{
    std::cout
        << '['
        << formatTimestamp(event.observed_at)
        << "] "
        << eventTypeToString(event)
        << ' ';

    printObservation(event.observation);
    std::cout << '\n';
}

netwatch::SocketSnapshot collectSnapshot(
    const netwatch::ProcSocketCollector& collector,
    const netwatch::ProcessResolver& resolver)
{
    const auto sockets = collector.collect();
    const auto owners = resolver.resolveSocketOwners();

    return netwatch::makeSocketSnapshot(
        sockets,
        owners
    );
}

} // namespace

int main(const int argc, char* argv[])
{
    Options options;

    try {
        options = parseOptions(argc, argv);
    } catch (const std::invalid_argument& error) {
        std::cerr
            << "Error: "
            << error.what()
            << "\n\n";

        printUsage();
        return 2;
    }

    if (options.help) {
        printUsage();
        return 0;
    }

    netwatch::ProcSocketCollector collector;
    netwatch::ProcessResolver resolver;

    auto previous = collectSnapshot(
        collector,
        resolver
    );

    if (options.once) {
        printSnapshot(previous);
        return 0;
    }

    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::cout
        << "NetWatch monitoring "
        << previous.size()
        << " sockets every "
        << options.interval.count()
        << " ms\n"
        << "Press Ctrl+C to stop.\n";

    netwatch::SnapshotDiffer differ;

    while (stopRequested == 0) {
        std::this_thread::sleep_for(options.interval);

        if (stopRequested != 0) {
            break;
        }

        auto current = collectSnapshot(
            collector,
            resolver
        );

        const auto events = differ.diff(
            previous,
            current,
            std::chrono::system_clock::now()
        );

        for (const auto& event : events) {
            printEvent(event);
        }

        previous = std::move(current);
    }

    std::cout << "NetWatch stopped.\n";

    return 0;
}
