#include "netwatch/procfs/ProcNetSocketParser.hpp"

namespace netwatch {

std::vector<SocketRecord> ProcNetSocketParser::parse(
    std::istream& input,
    const IpFamily family,
    const TransportProtocol protocol
) const
{
    (void)input;
    (void)family;
    (void)protocol;

    return {};
}

}