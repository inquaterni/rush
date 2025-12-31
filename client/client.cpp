//
// Created by inquaterni on 12/31/25.
//

#include "client.h"

#include <format>
#include <spdlog/spdlog.h>

#include "guard.h"

namespace enet {
    std::expected<client, std::string> client::create() noexcept {

        auto client_host = host{enet_host_create(nullptr /* create a client host */,
                                      1 /* only allow 1 outgoing connection */,
                                      2 /* allow up 2 channels to be used, 0 and 1 */,
                                      0 /* assume any amount of incoming bandwidth */,
                                      0 /* assume any amount of outgoing bandwidth */),
                     host_deleter{}};

        if (!client_host) {
            return std::unexpected{"Failed to create client."};
        }

        return client{std::move(client_host)};
    }
    bool client::connect(const std::string_view addr, const int port, const short timeout) noexcept {
        ENetAddress address{};
        ENetEvent event{};

        enet_address_set_host(&address, addr.data());
        address.port = port;
        auto server_peer = peer{enet_host_connect(host_.get(), &address, 2, 0), peer_deleter{}};

        if (!server_peer) {
            return false;
        }

        if (enet_host_service(host_.get(), &event, timeout) > 0 && event.type == ENET_EVENT_TYPE_CONNECT) {
            spdlog::info("Connection established.");
            server = std::move(server_peer);
            return true;
        }

        spdlog::error("Failed to establish connection.");
        return false;
    }
    client::client(host &&client) noexcept
    : host_(std::forward<host>(client)) {}
} // namespace enet
