//
// Created by inquaterni on 12/30/25.
//
#include <spdlog/spdlog.h>

#include "../core/include/guard.h"
#include "client.h"
#include "secure_session.h"

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    enet::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    sodium::guard::get_instance();

    enet::pkey_t public_key {};
    std::array<enet::u8, crypto_kx_SECRETKEYBYTES> secret_key {};

    crypto_kx_keypair(public_key.data(), secret_key.data());

    auto client = enet::client::create();
    if (!client) [[unlikely]] {
        spdlog::critical("Failed to create client: {}", client.error());
        return EXIT_FAILURE;
    }

    if (!client->connect("localhost", 6969)) {
        spdlog::critical("Failed to connect to server. Is server running?");
        return EXIT_FAILURE;
    }

    spdlog::info("Connected. Sending handshake...");

    const auto packet = enet::packet {enet::client_hs_payload(public_key)};
    client->send(packet);
    auto hs = client->recv<enet::server_hs_payload>();
    if (!hs) [[unlikely]] {
        spdlog::critical("Failed to establish secure connection: {}", hs.error());
        return EXIT_FAILURE;
    }
    const enet::pkey_t s_pub_key {hs->get_payload().public_key};
    std::array<enet::u8, crypto_kx_SESSIONKEYBYTES> rx {};
    std::array<enet::u8, crypto_kx_SESSIONKEYBYTES> tx {};

    if (crypto_kx_client_session_keys(rx.data(), tx.data(),
        public_key.data(), secret_key.data(),
        s_pub_key.data()) != 0) [[unlikely]] {
        spdlog::critical("Connection compromised. Aborting...");
        return EXIT_FAILURE;
    }

    spdlog::info("Established secure connection.");
    [[maybe_unused]]
    const auto ss = enet::secure_session {std::move(rx), std::move(tx)};

    return EXIT_SUCCESS;
}
