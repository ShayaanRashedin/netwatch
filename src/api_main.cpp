#include "netwatch/api/ApiServer.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#ifndef NETWATCH_WEB_ROOT
#define NETWATCH_WEB_ROOT "web"
#endif

namespace {

volatile std::sig_atomic_t stopRequested = 0;

void handleStopSignal(const int)
{
    stopRequested = 1;
}

struct Options {
    std::filesystem::path database {"netwatch.db"};
    std::filesystem::path web_root {NETWATCH_WEB_ROOT};
    std::string address {"127.0.0.1"};
    std::uint16_t port {8088U};
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

Options parseOptions(const int argc, char* argv[])
{
    Options options;

    for (int argumentIndex = 1;
         argumentIndex < argc;
         ++argumentIndex) {
        const std::string_view argument {argv[argumentIndex]};

        if (argument == "--help" || argument == "-h") {
            options.help = true;
            continue;
        }

        if (argument == "--database") {
            options.database = std::filesystem::path {
                std::string {requireValue(
                    argc,
                    argv,
                    argumentIndex,
                    argument
                )}
            };
            continue;
        }

        if (argument == "--web-root") {
            options.web_root = std::filesystem::path {
                std::string {requireValue(
                    argc,
                    argv,
                    argumentIndex,
                    argument
                )}
            };
            continue;
        }

        if (argument == "--listen") {
            options.address = requireValue(
                argc,
                argv,
                argumentIndex,
                argument
            );

            if (options.address.empty()) {
                throw std::invalid_argument {
                    "--listen requires a non-empty address"
                };
            }
            continue;
        }

        if (argument == "--port") {
            const std::string_view valueText = requireValue(
                argc,
                argv,
                argumentIndex,
                argument
            );
            std::uint32_t value {};

            const auto [ptr, error] = std::from_chars(
                valueText.data(),
                valueText.data() + valueText.size(),
                value
            );

            if (error != std::errc {}
                || ptr != valueText.data() + valueText.size()
                || value == 0U
                || value > 65'535U) {
                throw std::invalid_argument {
                    "--port must be between 1 and 65535"
                };
            }

            options.port = static_cast<std::uint16_t>(value);
            continue;
        }

        throw std::invalid_argument {
            "unknown option: " + std::string {argument}
        };
    }

    if (options.database.empty()) {
        throw std::invalid_argument {
            "--database requires a non-empty path"
        };
    }

    if (options.web_root.empty()) {
        throw std::invalid_argument {
            "--web-root requires a non-empty path"
        };
    }

    return options;
}

void printUsage()
{
    std::cout
        << "Usage: netwatch_api [OPTIONS]\n\n"
        << "  --database PATH  SQLite database path"
        << " (default: netwatch.db)\n"
        << "  --listen ADDRESS Bind address"
        << " (default: 127.0.0.1)\n"
        << "  --port VALUE     HTTP port"
        << " (default: 8088)\n"
        << "  --web-root PATH  Dashboard asset directory\n"
        << "  --help, -h       Show this help\n";
}

int run(const Options& options)
{
    netwatch::ApiServer server {
        options.database,
        options.web_root
    };

    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);

    std::atomic_bool serverExited {};
    bool listenSucceeded {};

    std::thread serverThread {[&] {
        listenSucceeded = server.listen(
            options.address,
            options.port
        );
        serverExited = true;
    }};

    std::cout
        << "NetWatch API and dashboard\n"
        << "Database: " << options.database << '\n'
        << "Dashboard: http://" << options.address
        << ':' << options.port << "/\n"
        << "Press Ctrl+C to stop.\n";

    while (stopRequested == 0 && !serverExited.load()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds {100}
        );
    }

    if (stopRequested != 0) {
        server.stop();
    }

    serverThread.join();

    if (!listenSucceeded && stopRequested == 0) {
        std::cerr
            << "Unable to listen on "
            << options.address << ':' << options.port << '\n';
        return 1;
    }

    std::cout << "NetWatch API stopped.\n";
    return 0;
}

} // namespace

int main(const int argc, char* argv[])
{
    try {
        const auto options = parseOptions(argc, argv);

        if (options.help) {
            printUsage();
            return 0;
        }

        return run(options);
    } catch (const std::invalid_argument& error) {
        std::cerr << "Error: " << error.what() << "\n\n";
        printUsage();
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}

