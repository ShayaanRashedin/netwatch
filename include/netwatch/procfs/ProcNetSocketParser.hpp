#pragma once

#include "netwatch/core/NetworkTypes.hpp"

#include <istream>
#include <vector>

namespace netwatch {

class ProcNetSocketParser {
public:
    [[nodiscard]]
    std::vector<SocketRecord> parse(
        std::istream& input,
        IpFamily family,
        TransportProtocol protocol
    ) const;
};

}