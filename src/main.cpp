#include "netwatch/core/NetworkTypes.hpp"
#include "netwatch/core/ProcessInfo.hpp"
#include "netwatch/core/SocketSnapshot.hpp"
#include "netwatch/detection/Alert.hpp"
#include "netwatch/detection/DetectionEngine.hpp"
#include "netwatch/monitoring/SnapshotDiffer.hpp"
#include "netwatch/persistence/EventWriter.hpp"
#include "netwatch/procfs/ProcessResolver.hpp"
#include "netwatch/procfs/ProcSocketCollector.hpp"
#include "netwatch/storage/SQLiteEventRepository.hpp"

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
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
    std::filesystem::path database {"netwatch.db"};
    std::size_t queue_capacity {1024U};
    std::uint64_t retention_days {30U};
    std::size_t history_limit {};
    std::size_t alerts_limit {};
    int minimum_risk_score {};
    bool persist {true};
    bool once {};
    bool help {};
};

std::string_view requireValue(
    const int argc,
    char* argv[],
    int& argumentIndex,
    const std::string_view option)
{
    if (argumentIndex + 1 >= argc) {
        throw std::invalid_argument {
            std::string {option} + " requires a value"
        };
    }

    ++argumentIndex;
    return argv[argumentIndex];
}

std::uint64_t parseUnsignedOption(
    const std::string_view option,
    const std::string_view valueText,
    const std::uint64_t minimum,
    const std::uint64_t maximum)
{
    std::uint64_t value {};

    const auto [ptr, error] = std::from_chars(
        valueText.data(),
        valueText.data() + valueText.size(),
        value
    );

    if (error != std::errc {}
        || ptr != valueText.data() + valueText.size()
        || value < minimum
        || value > maximum) {
        throw std::invalid_argument {
            std::string {option}
            + " must be between "
            + std::to_string(minimum)
            + " and "
            + std::to_string(maximum)
        };
    }

    return value;
}

Options parseOptions(const int argc, char* argv[])
{
    Options options;

    for (int argumentIndex = 1;
         argumentIndex < argc;
         ++argumentIndex) {
        const std::string_view argument {argv[argumentIndex]};

        if (argument == "--once") {
            options.once = true;
            continue;
        }

        if (argument == "--no-persist") {
            options.persist = false;
            continue;
        }

        if (argument == "--help" || argument == "-h") {
            options.help = true;
            continue;
        }

        if (argument == "--interval-ms") {
            const auto value = parseUnsignedOption(
                argument,
                requireValue(argc, argv, argumentIndex, argument),
                50U,
                3'600'000U
            );

            options.interval = std::chrono::milliseconds {
                static_cast<std::chrono::milliseconds::rep>(value)
            };
            continue;
        }

        if (argument == "--database") {
            const std::string_view path =
                requireValue(argc, argv, argumentIndex, argument);

            if (path.empty()) {
                throw std::invalid_argument {
                    "--database requires a non-empty path"
                };
            }

            options.database = std::filesystem::path {path};
            continue;
        }

        if (argument == "--queue-capacity") {
            const auto value = parseUnsignedOption(
                argument,
                requireValue(argc, argv, argumentIndex, argument),
                1U,
                1'000'000U
            );

            options.queue_capacity = static_cast<std::size_t>(value);
            continue;
        }

        if (argument == "--retention-days") {
            const std::string_view valueText =
                requireValue(argc, argv, argumentIndex, argument);

            if (valueText == "0") {
                options.retention_days = 0U;
                continue;
            }

            options.retention_days = parseUnsignedOption(
                argument,
                valueText,
                1U,
                36'500U
            );
            continue;
        }

        if (argument == "--history") {
            const auto value = parseUnsignedOption(
                argument,
                requireValue(argc, argv, argumentIndex, argument),
                1U,
                10'000U
            );

            options.history_limit = static_cast<std::size_t>(value);
            continue;
        }

        if (argument == "--alerts") {
            const auto value = parseUnsignedOption(
                argument,
                requireValue(argc, argv, argumentIndex, argument),
                1U,
                10'000U
            );

            options.alerts_limit = static_cast<std::size_t>(value);
            continue;
        }

        if (argument == "--min-score") {
            const auto value = parseUnsignedOption(
                argument,
                requireValue(argc, argv, argumentIndex, argument),
                0U,
                100U
            );

            options.minimum_risk_score = static_cast<int>(value);
            continue;
        }

        throw std::invalid_argument {
            "unknown option: " + std::string {argument}
        };
    }

    if (options.history_limit > 0U && options.once) {
        throw std::invalid_argument {
            "--history and --once cannot be used together"
        };
    }

    if (options.alerts_limit > 0U
        && (options.once || options.history_limit > 0U)) {
        throw std::invalid_argument {
            "--alerts cannot be combined with --once or --history"
        };
    }

    if (options.minimum_risk_score > 0
        && options.alerts_limit == 0U) {
        throw std::invalid_argument {
            "--min-score requires --alerts"
        };
    }

    return options;
}

void printUsage()
{
    std::cout
        << "Usage: netwatch [OPTIONS]\n"
        << "\n"
        << "  --once                  Print one snapshot and exit\n"
        << "  --interval-ms VALUE     Poll every 50-3600000 ms"
        << " (default: 1000)\n"
        << "  --database PATH         SQLite database path"
        << " (default: netwatch.db)\n"
        << "  --queue-capacity VALUE  Bounded writer queue size"
        << " (default: 1024)\n"
        << "  --retention-days VALUE  Delete older events on start"
        << " (default: 30; 0 disables)\n"
        << "  --history LIMIT         Print recent persisted events"
        << " and exit\n"
        << "  --alerts LIMIT          Print recent persisted alerts"
        << " and exit\n"
        << "  --min-score VALUE       Filter --alerts to risk score"
        << " 0-100\n"
        << "  --no-persist            Monitor without writing SQLite\n"
        << "  --help, -h              Show this help\n";
}

std::string_view familyToString(const netwatch::IpFamily family)
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

std::string eventTypeToString(const netwatch::SocketEvent& event)
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
                    socketStateToString(event.observation.socket.state)
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
            << '[' << endpoint.address << "]:" << endpoint.port;
        return;
    }

    std::cout << endpoint.address << ':' << endpoint.port;
}

void printProcess(const netwatch::ProcessInfo& process)
{
    std::cout
        << " owner={pid=" << process.pid
        << " process=" << process.name;

    if (process.uid.has_value()) {
        std::cout << " uid=" << *process.uid;
    }
    if (!process.username.empty()) {
        std::cout << " user=" << process.username;
    }
    if (!process.executable.empty()) {
        std::cout << " exe=" << process.executable;
    }
    if (!process.command_line.empty()) {
        std::cout << " cmd=\"" << process.command_line << '"';
    }
    if (process.start_time_ticks.has_value()) {
        std::cout << " start_ticks=" << *process.start_time_ticks;
    }

    std::cout << '}';
}

void printObservation(const netwatch::ObservedSocket& observation)
{
    const auto& socket = observation.socket;

    std::cout
        << protocolToString(socket.protocol) << ' '
        << familyToString(socket.family) << ' ';

    printEndpoint(socket.local, socket.family);
    std::cout << " -> ";
    printEndpoint(socket.remote, socket.family);

    std::cout
        << ' ' << socketStateToString(socket.state)
        << " inode=" << socket.inode
        << " tx=" << socket.tx_queue_bytes
        << " rx=" << socket.rx_queue_bytes;

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
        << "Sockets found: " << snapshot.size() << "\n\n";

    for (const auto& [key, observation] : snapshot) {
        static_cast<void>(key);
        printObservation(observation);
        std::cout << '\n';
    }
}

void printEvent(const netwatch::SocketEvent& event)
{
    std::cout
        << '[' << formatTimestamp(event.observed_at) << "] "
        << eventTypeToString(event) << ' ';

    printObservation(event.observation);
    std::cout << '\n';
}

void printAlert(const netwatch::Alert& alert)
{
    std::cout
        << '[' << formatTimestamp(alert.detected_at) << "] ALERT"
        << " severity="
        << netwatch::alertSeverityToString(alert.severity)
        << " score=" << alert.risk_score
        << " rule=" << alert.rule_id
        << " title=\"" << alert.title << "\"\n"
        << "  reason: " << alert.reason << '\n';

    for (const auto& evidence : alert.evidence) {
        std::cout << "  evidence: " << evidence << '\n';
    }
}

netwatch::SocketSnapshot collectSnapshot(
    const netwatch::ProcSocketCollector& collector,
    const netwatch::ProcessResolver& resolver)
{
    return netwatch::makeSocketSnapshot(
        collector.collect(),
        resolver.resolveSocketOwners()
    );
}

int showHistory(const Options& options)
{
    netwatch::SQLiteEventRepository repository {options.database};
    const auto events = repository.recentEvents(options.history_limit);

    std::cout
        << "NetWatch persisted event history\n"
        << "Database: " << options.database << '\n'
        << "Events shown: " << events.size() << "\n\n";

    for (const auto& stored : events) {
        std::cout << '#' << stored.id << ' ';
        printEvent(stored.event);
    }

    return 0;
}

int showAlerts(const Options& options)
{
    netwatch::SQLiteEventRepository repository {options.database};
    const auto alerts = repository.recentAlerts(
        options.alerts_limit,
        options.minimum_risk_score
    );

    std::cout
        << "NetWatch persisted alert history\n"
        << "Database: " << options.database << '\n'
        << "Minimum risk score: "
        << options.minimum_risk_score << '\n'
        << "Alerts shown: " << alerts.size() << "\n\n";

    for (const auto& stored : alerts) {
        std::cout
            << "alert_id=" << stored.id
            << " event_id=" << stored.event_id << '\n';
        printAlert(stored.alert);
        std::cout << "  source: ";
        printEvent(stored.alert.source_event);
        std::cout << '\n';
    }

    return 0;
}

int monitor(const Options& options)
{
    netwatch::ProcSocketCollector collector;
    netwatch::ProcessResolver resolver;

    auto previous = collectSnapshot(collector, resolver);

    if (options.once) {
        printSnapshot(previous);
        return 0;
    }

    std::size_t deletedEvents {};

    if (options.persist && options.retention_days > 0U) {
        netwatch::SQLiteEventRepository repository {options.database};

        const auto retention = std::chrono::hours {
            static_cast<std::chrono::hours::rep>(
                options.retention_days * 24U
            )
        };

        deletedEvents = repository.deleteEventsOlderThan(
            std::chrono::system_clock::now() - retention
        );
    }

    std::unique_ptr<netwatch::EventWriter> writer;

    if (options.persist) {
        writer = std::make_unique<netwatch::EventWriter>(
            options.database,
            options.queue_capacity
        );
    }

    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::cout
        << "NetWatch monitoring " << previous.size()
        << " sockets every " << options.interval.count() << " ms\n";

    if (writer) {
        std::cout
            << "Persisting events to " << options.database
            << " with queue capacity " << options.queue_capacity
            << " (pruned " << deletedEvents << " old events)\n";
    } else {
        std::cout << "SQLite persistence disabled.\n";
    }

    std::cout << "Press Ctrl+C to stop.\n";

    netwatch::SnapshotDiffer differ;
    netwatch::DetectionEngine detector;

    while (stopRequested == 0) {
        std::this_thread::sleep_for(options.interval);

        if (stopRequested != 0) {
            break;
        }

        auto current = collectSnapshot(collector, resolver);

        const auto events = differ.diff(
            previous,
            current,
            std::chrono::system_clock::now()
        );

        for (const auto& event : events) {
            printEvent(event);

            const auto alerts = detector.evaluate(event);

            for (const auto& alert : alerts) {
                printAlert(alert);
            }

            if (writer && !writer->submit(event, alerts)) {
                std::cerr
                    << "Persistence queue closed unexpectedly.\n";
                stopRequested = 1;
                break;
            }
        }

        previous = std::move(current);
    }

    if (writer) {
        writer->stop();

        if (const auto failure = writer->failure()) {
            std::cerr
                << "Persistence failed: " << *failure << '\n';
            return 1;
        }

        std::cout
            << "Persisted " << writer->persistedCount()
            << " events and "
            << writer->persistedAlertCount()
            << " alerts.\n";
    }

    std::cout << "NetWatch stopped.\n";
    return 0;
}

} // namespace

int main(const int argc, char* argv[])
{
    Options options;

    try {
        options = parseOptions(argc, argv);
    } catch (const std::invalid_argument& error) {
        std::cerr << "Error: " << error.what() << "\n\n";
        printUsage();
        return 2;
    }

    if (options.help) {
        printUsage();
        return 0;
    }

    try {
        if (options.history_limit > 0U) {
            return showHistory(options);
        }

        if (options.alerts_limit > 0U) {
            return showAlerts(options);
        }

        return monitor(options);
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}

