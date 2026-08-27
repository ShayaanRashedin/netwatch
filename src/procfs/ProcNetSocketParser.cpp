#include "netwatch/procfs/ProcNetSocketParser.hpp"

#include <arpa/inet.h>

#include <array>
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

    if (!value.has_value()
        || *value > std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }

    return static_cast<std::uint16_t>(*value);
}

std::optional<std::string> parseIPv4Address(
    const std::string_view text)
{
    if (text.size() != 8U) {
        return std::nullopt;
    }

    std::string address;

    // procfs exposes IPv4 bytes in host-order hexadecimal.
    for (int byteIndex = 3; byteIndex >= 0; --byteIndex) {
        const std::size_t position =
            static_cast<std::size_t>(byteIndex) * 2U;

        const auto byte =
            parseUnsigned(text.substr(position, 2U), 16);

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

std::optional<std::string> parseIPv6Address(
    const std::string_view text)
{
    if (text.size() != 32U) {
        return std::nullopt;
    }

    std::array<unsigned char, 16> bytes {};

    // Each 32-bit word in the procfs IPv6 value is host ordered.
    for (std::size_t wordIndex = 0; wordIndex < 4U; ++wordIndex) {
        for (std::size_t byteIndex = 0; byteIndex < 4U; ++byteIndex) {
            const std::size_t sourcePosition =
                (wordIndex * 8U) + ((3U - byteIndex) * 2U);

            const auto byte = parseUnsigned(
                text.substr(sourcePosition, 2U),
                16
            );

            if (!byte.has_value() || *byte > 255U) {
                return std::nullopt;
            }

            bytes[(wordIndex * 4U) + byteIndex] =
                static_cast<unsigned char>(*byte);
        }
    }

    std::array<char, INET6_ADDRSTRLEN> address {};

    const auto* result = ::inet_ntop(
        AF_INET6,
        bytes.data(),
        address.data(),
        static_cast<socklen_t>(address.size())
    );

    if (result == nullptr) {
        return std::nullopt;
    }

    return std::string {address.data()};
}

std::optional<Endpoint> parseEndpoint(
    const std::string_view text,
    const IpFamily family)
{
    const std::size_t separator = text.find(':');

    if (separator == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view addressText =
        text.substr(0, separator);

    const std::string_view portText =
        text.substr(separator + 1U);

    const auto address =
        family == IpFamily::IPv4
            ? parseIPv4Address(addressText)
            : parseIPv6Address(addressText);

    const auto port = parseHexPort(portText);

    if (!address.has_value() || !port.has_value()) {
        return std::nullopt;
    }

    Endpoint endpoint;
    endpoint.address = *address;
    endpoint.port = *port;

    return endpoint;
}

SocketState parseSocketState(
    const std::string_view state,
    const TransportProtocol protocol)
{
    if (protocol == TransportProtocol::Udp) {
        if (state == "01") {
            return SocketState::Established;
        }

        if (state == "07") {
            return SocketState::Unconnected;
        }

        return SocketState::Unknown;
    }

    if (state == "01") {
        return SocketState::Established;
    }

    if (state == "02") {
        return SocketState::SynSent;
    }

    if (state == "03") {
        return SocketState::SynReceived;
    }

    if (state == "04") {
        return SocketState::FinWait1;
    }

    if (state == "05") {
        return SocketState::FinWait2;
    }

    if (state == "06") {
        return SocketState::TimeWait;
    }

    if (state == "07") {
        return SocketState::Closed;
    }

    if (state == "08") {
        return SocketState::CloseWait;
    }

    if (state == "09") {
        return SocketState::LastAck;
    }

    if (state == "0A") {
        return SocketState::Listen;
    }

    if (state == "0B") {
        return SocketState::Closing;
    }

    if (state == "0C") {
        return SocketState::NewSynReceived;
    }

    return SocketState::Unknown;
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
        parseUnsigned(text.substr(separator + 1U), 16);

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

    // Fields through index 9 are required to reach the inode column.
    if (fields.size() < 10U) {
        return std::nullopt;
    }

    const auto local = parseEndpoint(fields[1], family);
    const auto remote = parseEndpoint(fields[2], family);
    const auto queues = parseQueueSizes(fields[4]);

    // The inode field is decimal; most address-table fields are hexadecimal.
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
    record.state = parseSocketState(fields[3], protocol);
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
    std::string line;

    // Every procfs socket table begins with one column-header line.
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

} // namespace netwatch
