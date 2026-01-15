//
// Created by inquaterni on 12/30/25.
//
#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "cipher.h"
#include "host.h"
#include "key_pair.h"
#include "packet.h"
#include "state.h"
#include "xchacha20poly1305.h"

#include "spdlog/spdlog.h"

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    net::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    crypto::guard::get_instance();

    auto server = net::host::create(ENET_HOST_ANY, 6969);
    if (!server) {
        spdlog::critical("Failed to create server: {}", server.error());
        return EXIT_FAILURE;
    }
    auto keys = crypto::key_pair::enroll();
    if (!keys) {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }
    server.value()->service();
    spdlog::info("Server is initialized");

    while (true) {
        auto e = server.value()->recv();
        if (!e) {
            // spdlog::critical("Failed to receive message: {}", e.error());
            continue;
        }

        std::visit<void>(net::overloaded {
            [&] (const net::connect_event &ce) {
                ce.peer()->data = static_cast<void *>(new net::peer_context {*server, net::handshake {*keys}});
            },
            [&] (net::receive_event &re) {
                const auto ctx = static_cast<net::peer_context *>(re.peer()->data);
                ctx->handle(re);
            },
            [&] (net::disconnect_event &de) {
                if (const auto ctx = static_cast<net::peer_context *>(de.peer()->data)) {
                    delete ctx;
                    de.set_peer(nullptr);
                }
            }
        }, e.value());
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    return EXIT_SUCCESS;
}
