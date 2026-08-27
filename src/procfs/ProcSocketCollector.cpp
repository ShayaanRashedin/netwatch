#include "netwatch/procfs/ProcSocketCollector.hpp"

#include "netwatch/procfs/ProcNetSocketParser.hpp"

#include <array>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>

namespace netwatch {

namespace {

struct SocketTable {
    std::string_view filename;
    IpFamily family;
    TransportProtocol protocol;
};

constexpr std::array<SocketTable, 4> socketTables {{
    {"tcp", IpFamily::IPv4, TransportProtocol::Tcp},
    {"tcp6", IpFamily::IPv6, TransportProtocol::Tcp},
    {"udp", IpFamily::IPv4, TransportProtocol::Udp},
    {"udp6", IpFamily::IPv6, TransportProtocol::Udp}
}};

} // namespace

ProcSocketCollector::ProcSocketCollector(
    std::filesystem::path procNetRoot)
    : proc_net_root_ {std::move(procNetRoot)}
{
}

std::vector<SocketRecord> ProcSocketCollector::collect() const
{
    ProcNetSocketParser parser;
    std::vector<SocketRecord> records;

    for (const auto& table : socketTables) {
        std::ifstream input {
            proc_net_root_ / std::string {table.filename}
        };

        if (!input.is_open()) {
            continue;
        }

        auto tableRecords = parser.parse(
            input,
            table.family,
            table.protocol
        );

        for (auto& record : tableRecords) {
            records.push_back(std::move(record));
        }
    }

    return records;
}

} // namespace netwatch
