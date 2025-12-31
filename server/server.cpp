//
// Created by inquaterni on 12/30/25.
//

#include "server.h"
#include <utility>
#include "guard.h"

namespace enet {
    std::expected<server, std::string> server::create(const in6_addr addr, const int port) {
        if (!guard::is_initialized()) [[unlikely]] {
            return std::unexpected("ENet context is not initialized.");
        }

        ENetAddress address{};
        address.host = addr;
        address.port = port;

        auto server_host = host{enet_host_create(&address /* the address to bind the server host to */,
                                                 max_clients /* allow up to 32 clients and/or outgoing connections */,
                                                 2 /* allow up to 2 channels to be used, 0 and 1 */,
                                                 0 /* assume any amount of incoming bandwidth */,
                                                 0 /* assume any amount of outgoing bandwidth */),
                                enet::host_deleter{}};

        if (!server_host) {
            return std::unexpected("An error occurred while trying to create an ENet server host.\n");
        }

        return server{std::move(server_host)};
    }
    server::server(host &&s) noexcept : host_{std::forward<host>(s)} {}
} // namespace enet
