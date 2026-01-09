//
// Created by inquaterni on 12/30/25.
//
#include <iostream>
#include <spdlog/spdlog.h>

#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "chacha20poly1305.h"
#include "cipher.h"
#include "client.h"
#include "key_pair.h"
#include "secure_session.h"
#include "secure_session_factory.h"

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    net::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    crypto::guard::get_instance();

    auto client = net::client::create();
    if (!client) [[unlikely]] {
        spdlog::critical("Failed to create client: {}", client.error());
        return EXIT_FAILURE;
    }

    auto keys = crypto::key_pair::enroll();
    if (!keys) [[unlikely]] {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }

    if (!client->connect("localhost", 6969)) {
        spdlog::critical("Failed to connect to server. Is server running?");
        return EXIT_FAILURE;
    }

    client->service(16);

    spdlog::info("Connected. Sending handshake...");

    if (!client->send(net::client_hs_packet {keys->cpublic_key()})) [[unlikely]] {
        spdlog::critical("Failed to send handshake.");
        return EXIT_FAILURE;
    }
    auto hs = client->recv<net::server_hs_packet>();
    while (!hs) {
        hs = client->recv<net::server_hs_packet>();
        if (!hs) [[unlikely]] {
            spdlog::warn("Failed to receive handshake: {}", hs.error());
        }
    }
    const auto ss = crypto::secure_session_factory::enroll<crypto::side::CLIENT>(keys.value(), hs->public_key);
    if (!ss) [[unlikely]] {
        spdlog::critical("Failed to establish secure session: {}", ss.error());
    }

    const auto cipher = crypto::cipher {std::make_unique<crypto::chacha20poly1305>(ss.value())};

    spdlog::info("Handshake completed.");

    std::string prompt {};
    while (true) {
        std::getline(std::cin, prompt);
        if (prompt == "quit") {break;}
        const auto message = std::vector<net::u8> {prompt.begin(), prompt.end()};
        const auto encrypted = cipher.encrypt(message);
        if (!encrypted) [[unlikely]] {
            continue;
        }
        const auto packet = net::packet<net::packet_type::ENCRYPTED_CHACHA20POLY1305> {encrypted.value()};
        if (!client->send(packet)) {
            spdlog::critical("Failed to send packet.");
        }

        prompt.clear();
    }

    return EXIT_SUCCESS;
}
