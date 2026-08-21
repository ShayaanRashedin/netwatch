#include "netwatch/procfs/ProcNetSocketParser.hpp"

#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace netwatch {

namespace {

std::optional<std::uint64_t> parseUnsigned(
    const std::string_view text,
    const int base)
{
    std::uint64_t value {};

    const char* begin = text.data();
    const char* end = text.data() + text.size();

    const auto [ptr, error] =
        std::from_chars(begin, end, value, base);

    if (error != std::errc {} || ptr != end) {
        return std::nullopt;
    }

    return value;
}

std::optional<std::uint16_t> parseHexPort(
    const std::string_view text)
{
    const auto value = parseUnsigned(text, 16);

    if (!value.has_value()) {
        return std::nullopt;
    }

    if (*value > std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }

    return static_cast<std::uint16_t>(*value);
}

std::optional<std::string> parseIPv4Address(
    const std::string_view text)
{
    if (text.size() != 8) {
        return std::nullopt;
    }

    std::string address;

    // /proc/net/tcp represents IPv4 bytes in little-endian order.
    for (int byteIndex = 3; byteIndex >= 0; --byteIndex) {
        const std::size_t position =
            static_cast<std::size_t>(byteIndex) * 2U;

        const auto byte =
            parseUnsigned(text.substr(position, 2), 16);

        if (!byte.has_value() || *byte > 255U) {
            return std::nullopt;
        }

        if (!address.empty()) {
            address += '.';
        }

        address += std::to_string(*byte);
    }

    return address;
}

std::optional<Endpoint> parseEndpoint(
    const std::string_view text)
{
    const std::size_t separator = text.find(':');

    if (separator == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view addressText =
        text.substr(0, separator);

    const std::string_view portText =
        text.substr(separator + 1);

    const auto address = parseIPv4Address(addressText);
    const auto port = parseHexPort(portText);

    if (!address.has_value() || !port.has_value()) {
        return std::nullopt;
    }

    Endpoint endpoint;
    endpoint.address = *address;
    endpoint.port = *port;

    return endpoint;
}

TcpState parseTcpState(const std::string_view state)
{
    if (state == "01") {
        return TcpState::Established;
    }

    if (state == "02") {
        return TcpState::SynSent;
    }

    if (state == "03") {
        return TcpState::SynReceived;
    }

    if (state == "04") {
        return TcpState::FinWait1;
    }

    if (state == "05") {
        return TcpState::FinWait2;
    }

    if (state == "06") {
        return TcpState::TimeWait;
    }

    if (state == "07") {
        return TcpState::Closed;
    }

    if (state == "08") {
        return TcpState::CloseWait;
    }

    if (state == "09") {
        return TcpState::LastAck;
    }

    if (state == "0A") {
        return TcpState::Listen;
    }

    if (state == "0B") {
        return TcpState::Closing;
    }

    return TcpState::Unknown;
}

std::optional<std::pair<std::uint64_t, std::uint64_t>>
parseQueueSizes(const std::string_view text)
{
    const std::size_t separator = text.find(':');

    if (separator == std::string_view::npos) {
        return std::nullopt;
    }

    const auto txQueue =
        parseUnsigned(text.substr(0, separator), 16);

    const auto rxQueue =
        parseUnsigned(text.substr(separator + 1), 16);

    if (!txQueue.has_value() || !rxQueue.has_value()) {
        return std::nullopt;
    }

    return std::pair {*txQueue, *rxQueue};
}

std::optional<SocketRecord> parseSocketLine(
    const std::string_view line,
    const IpFamily family,
    const TransportProtocol protocol)
{
    std::istringstream stream {std::string {line}};

    std::vector<std::string> fields;
    std::string field;

    while (stream >> field) {
        fields.push_back(field);
    }

    // We need fields through the inode column.
    if (fields.size() < 10) {
        return std::nullopt;
    }

    const auto local = parseEndpoint(fields[1]);
    const auto remote = parseEndpoint(fields[2]);
    const auto queues = parseQueueSizes(fields[4]);

    // The inode field is decimal, unlike many other procfs fields here.
    const auto inode = parseUnsigned(fields[9], 10);

    if (!local.has_value()
        || !remote.has_value()
        || !queues.has_value()
        || !inode.has_value()) {
        return std::nullopt;
    }

    SocketRecord record;

    record.family = family;
    record.protocol = protocol;

    record.local = *local;
    record.remote = *remote;

    record.state = parseTcpState(fields[3]);

    record.tx_queue_bytes = queues->first;
    record.rx_queue_bytes = queues->second;

    record.inode = *inode;

    return record;
}

} // namespace

std::vector<SocketRecord> ProcNetSocketParser::parse(
    std::istream& input,
    const IpFamily family,
    const TransportProtocol protocol) const
{
    std::vector<SocketRecord> records;

    // Current implementation supports IPv4 only.
    if (family != IpFamily::IPv4) {
        return records;
    }

    std::string line;

    // Skip the column-header line.
    if (!std::getline(input, line)) {
        return records;
    }

    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }

        const auto record =
            parseSocketLine(line, family, protocol);

        if (record.has_value()) {
            records.push_back(*record);
        }
    }

    return records;
}

}