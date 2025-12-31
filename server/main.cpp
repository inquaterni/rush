//
// Created by inquaterni on 12/30/25.
//
#include "guard.h"
#include "packet.h"
#include "secure_session.h"
#include "server.h"
#include "spdlog/spdlog.h"

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    enet::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    sodium::guard::get_instance();

    enet::pkey_t public_key {};
    std::array<enet::u8, crypto_kx_SECRETKEYBYTES> secret_key {};

    crypto_kx_keypair(public_key.data(), secret_key.data());

    auto server = enet::server::create(ENET_HOST_ANY, 6969);
    if (!server) {
        spdlog::critical("Failed to create server: {}", server.error());
        return EXIT_FAILURE;
    }

    spdlog::info("Server is initialized");

    auto hs = server->recv<enet::client_hs_payload>(10000);
    if (!hs) [[unlikely]] {
        spdlog::critical("Failed to receive client's handshake: {}", hs.error());
        return EXIT_FAILURE;
    }

    const enet::pkey_t c_pub_key {hs->get_payload().public_key};
    std::array<enet::u8, crypto_kx_SESSIONKEYBYTES> rx {};
    std::array<enet::u8, crypto_kx_SESSIONKEYBYTES> tx {};
    if (crypto_kx_server_session_keys(rx.data(), tx.data(),
                                      public_key.data(), secret_key.data(),
                                      c_pub_key.data()) != 0) [[unlikely]] {
        spdlog::critical("Connection compromised. Aborting...");
        return EXIT_FAILURE;
    }
    if (!server->send(enet::packet { enet::server_hs_payload {public_key} })) [[unlikely]] {
        spdlog::critical("Failed to exchange keys. Aborting...");
        return EXIT_FAILURE;
    }

    spdlog::info("Established secure connection.");
    [[maybe_unused]]
    const auto ss = enet::secure_session {std::move(rx), std::move(tx)};

    return EXIT_SUCCESS;
}
