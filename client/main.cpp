//
// Created by inquaterni on 12/30/25.
//
#include <iostream>
#include <spdlog/spdlog.h>

#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "guard.h"
#include "../server/state.h"
#include "cipher.h"
#include "client.h"
#include "key_pair.h"
#include "keys_factory.h"
#include "xchacha20poly1305.h"

void clear_terminal() {
    constexpr char clear_seq[] = "\033[2J\033[H";
    write(STDOUT_FILENO, clear_seq, sizeof(clear_seq) - 1);
}

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
    if (!net::is_confirm<crypto::side::CLIENT>(*original)) [[unlikely]] {
        spdlog::critical("Confirmation magic was corrupted or wrong: {}", original.error());
        return EXIT_FAILURE;
    }

    spdlog::info("Handshake completed.");
    spdlog::info("Session established. Entering raw mode.");
    spdlog::default_logger()->flush();
    std::cout << std::flush;
    std::cerr << std::flush;

    auto &term = term::guard::get_instance();
    if (!term.enable_raw_mode()) {
        spdlog::critical("Failed to enable raw terminal mode.");
        return EXIT_FAILURE;
    }

    std::jthread network_listener([&] (const std::stop_token &st) {
        while (!st.stop_requested()) {
            auto pkt = client->recv();

            if (!pkt) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            const auto *const g_pkt = std::get_if<net::generic_packet>(&*pkt);
            if (!g_pkt || g_pkt->type != net::packet_type::XCHACHA20POLY1305) continue;
            const auto dcryp = cipher.decrypt(g_pkt->body);
            if (!dcryp) {
                // spdlog::warn("Failed to decrypt incoming packet: {}", dcryp.error());
                continue;
            }
            const auto orig = pack::compressor::decompress(*dcryp);
            if (!orig) {
                // spdlog::warn("Failed to decompress incoming packet: {}", orig.error());
                continue;
            }

            if (!orig->empty()) {
                // clear_terminal();
                write(STDOUT_FILENO, orig->data(), orig->size());
            }
        }
    });

    std::array<char, 1024 * 4> buffer {};
    constexpr auto fds_size = 1;
    std::array<pollfd, fds_size> fds{};
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    while (true) {
        if (auto ret = poll(fds.data(), fds_size, 1); ret < 0) [[unlikely]] {
            spdlog::error("Poll error: {}", ret);
            break;
        }

        if (fds[0].revents & POLLIN) {
            if (const auto n = read(STDIN_FILENO, buffer.data(), buffer.size()); n > 0) {
                if (n == 1 && buffer[0] == 0x04) {
                    term.disable_raw_mode();
                    spdlog::info("Ctrl+D pressed. Exiting client ...");
                    break;
                }
                const auto data = std::vector<net::u8>  {buffer.data(), buffer.data() + n};
                const auto cmprsd = pack::compressor::compress(data);
                if (!cmprsd) [[unlikely]] {
                    // spdlog::error("Failed to compress data: {}", cmprsd.error());
                    continue;
                }
                const auto enc = cipher.encrypt(*cmprsd);
                if (!enc) [[unlikely]] {
                    // spdlog::error("Failed to encrypt data: {}", enc.error());
                    continue;
                }
                if (!client->send(net::generic_packet {net::packet_type::XCHACHA20POLY1305, *enc})) {
                    // spdlog::error("Failed to send data.");
                }
            } else if (n == 0) break;
        }
    }

    return EXIT_SUCCESS;
}
