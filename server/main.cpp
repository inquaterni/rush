//
// Created by inquaterni on 12/30/25.
//
#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "cipher.h"
#include "key_pair.h"
#include "packet.h"
#include "secure_session_factory.h"
#include "server.h"

#include "spdlog/spdlog.h"

[[noreturn]] int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    net::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    crypto::guard::get_instance();

    auto server = net::server::create(ENET_HOST_ANY, 6969);
    if (!server) {
        spdlog::critical("Failed to create server: {}", server.error());
        return EXIT_FAILURE;
    }
    auto keys = crypto::key_pair::enroll();
    if (!keys) {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }

    spdlog::info("Server is initialized");

    auto hs = server->recv<net::client_hs_packet>(10'000);
    if (!hs) [[unlikely]] {
        spdlog::critical("Failed to receive HS packet: {}", hs.error());
        return EXIT_FAILURE;
    }

    auto ss = crypto::secure_session_factory::enroll<crypto::side::SERVER>(keys.value(), hs->public_key);
    if (!ss) [[unlikely]] {
        spdlog::critical("Failed to create secure connection: {}", ss.error());
    }
    if (!server->send(net::server_hs_packet { keys->cpublic_key() })) [[unlikely]] {
        spdlog::critical("Failed to send HS packet.");
        return EXIT_FAILURE;
    }
    const auto cipher = crypto::cipher {std::make_unique<crypto::chacha20poly1305>(ss.value())};

    spdlog::info("Established secure connection.");

    while (true) {
        const auto encrypted = server->recv<net::packet<net::packet_type::ENCRYPTED_CHACHA20POLY1305>>(16);
        if (!encrypted) [[unlikely]] {
            // spdlog::warn("Failed to receive ENCRYPTED_CHACHA20POLY1305 packet: {}.", encrypted.error());
            continue;
        }

        const auto msg = cipher.decrypt(encrypted.value().body);
        if (!msg) [[unlikely]] {
            spdlog::warn("Failed to decrypt encrypted packet: {}.", msg.error());
            continue;
        }

        const auto str = std::string {msg.value().begin(), msg.value().end()};

        spdlog::info("Received encrypted message: '{}'.", str);
    }

    return EXIT_SUCCESS;
}
