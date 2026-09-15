#include "netwatch/core/SocketSnapshot.hpp"

#include <utility>

namespace netwatch {

SocketKey makeSocketKey(const SocketRecord& socket)
{
    SocketKey key;

    key.family = socket.family;
    key.protocol = socket.protocol;

    key.local_address = socket.local.address;
    key.local_port = socket.local.port;

    key.remote_address = socket.remote.address;
    key.remote_port = socket.remote.port;

    key.inode = socket.inode;

    return key;
}

SocketSnapshot makeSocketSnapshot(
    const std::vector<SocketRecord>& sockets,
    const SocketOwnerMap& owners)
{
    SocketSnapshot snapshot;

    for (const auto& socket : sockets) {
        ObservedSocket observation;
        observation.socket = socket;

        const auto owner = owners.find(socket.inode);

        if (owner != owners.end()) {
            observation.owners = owner->second;
        }

        snapshot.insert_or_assign(
            makeSocketKey(socket),
            std::move(observation)
        );
    }

    return snapshot;
}

} // namespace netwatch
