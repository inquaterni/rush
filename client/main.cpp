//
// Created by inquaterni on 12/30/25.
//
#include <iostream>
#include <spdlog/spdlog.h>

#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "../server/state.h"
#include "cipher.h"
#include "client.h"
#include "key_pair.h"
#include "keys_factory.h"
#include "xchacha20poly1305.h"

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

    if (!client->send(net::handshake_packet {keys->cpublic_key()})) [[unlikely]] {
        spdlog::critical("Failed to send handshake.");
        return EXIT_FAILURE;
    }
    auto hs = client->recv();
    auto i = 0;
    while (!hs && i++ < 1'000) {
        hs = client->recv();
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    if (!hs) [[unlikely]] {
        spdlog::critical("Failed to receive handshake: {}", hs.error());
        return EXIT_FAILURE;
    }

    const auto key = std::visit(net::overloaded {
        [&] (const net::handshake_packet &p) -> std::expected<crypto::pkey_t, std::string> {
            return p.public_key;
        },
        [&] (const auto &) -> std::expected<crypto::pkey_t, std::string> {
            return std::unexpected<std::string> { "Wrong packet type." };
        }
    }, hs.value());

    if (!key) {
        spdlog::critical("Failed to retrieve public key: {}", key.error());
        return EXIT_FAILURE;
    }

    const auto ss = crypto::keys_factory::enroll<crypto::side::CLIENT>(keys.value(), key.value());
    if (!ss) [[unlikely]] {
        spdlog::critical("Failed to establish secure session: {}", ss.error());
    }

    const auto cipher = crypto::cipher {std::make_unique<crypto::xchacha20poly1305>(ss.value())};

    const auto compressed = pack::compressor::compress(std::span {net::c_confirm_magic, sizeof(net::c_confirm_magic)});
    if (!compressed) [[unlikely]] {
        spdlog::critical("Failed to confirm connection establishment: {}", compressed.error());
        return EXIT_FAILURE;
    }
    const auto encrypted = cipher.encrypt(*compressed);
    if (!encrypted) [[unlikely]] {
        spdlog::critical("Failed to confirm connection establishment: {}", encrypted.error());
        return EXIT_FAILURE;
    }
    if (!client->send(net::generic_packet {net::packet_type::XCHACHA20POLY1305, *encrypted})) {
        spdlog::critical("Failed to send encrypted confirmation: {}", encrypted.error());
        return EXIT_FAILURE;
    }

    auto conf = client->recv();
    auto j = 0;
    while (!conf && j++ < 1'000) {
        conf = client->recv();
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    if (!conf) [[unlikely]] {
        spdlog::critical("Failed to receive confirmation: {}", conf.error());
        return EXIT_FAILURE;
    }

    const auto confirm_msg = std::get_if<net::generic_packet>(&*conf);
    if (!confirm_msg || confirm_msg->type != net::packet_type::XCHACHA20POLY1305) [[unlikely]] {
        spdlog::critical("Failed to receive confirmation: No viable packet");
        return EXIT_FAILURE;
    }
    const auto decrypted = cipher.decrypt(confirm_msg->body);
    if (!decrypted) [[unlikely]] {
        spdlog::critical("Failed to decrypt confirmation: {}", decrypted.error());
        return EXIT_FAILURE;
    }
    const auto original = pack::compressor::decompress(*decrypted);
    if (!original) [[unlikely]] {
        spdlog::critical("Failed to decompress confirmation: {}", original.error());
        return EXIT_FAILURE;
    }
    if (!net::is_s_confirm(*original)) [[unlikely]] {
        spdlog::critical("Confirmation magic was corrupted or wrong: {}", original.error());
        return EXIT_FAILURE;
    }

    spdlog::info("Handshake completed.");

    std::string prompt {};
    while (true) {
        std::getline(std::cin, prompt);
        if (prompt == "quit") {break;}
        std::cout << "Message length: " << prompt.length() << std::endl;
        const auto message = std::vector<net::u8> {prompt.begin(), prompt.end()};
        const auto c = pack::compressor::compress(message);
        if (!c) [[unlikely]] {
            continue;
        }
        const auto e = cipher.encrypt(*c);
        if (!e) [[unlikely]] {
            continue;
        }
        if (!client->send(net::generic_packet {net::packet_type::XCHACHA20POLY1305, e.value()})) {
            spdlog::critical("Failed to send packet.");
        }

        prompt.clear();
    }

    return EXIT_SUCCESS;
}
