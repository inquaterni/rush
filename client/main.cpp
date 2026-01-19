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
#include "signals.hpp"
#include "xchacha20poly1305.h"

#include <sys/signalfd.h>


static constexpr auto key_map = std::to_array<std::pair<net::u8, int>>({
    { 0x03, SIGINT },
    { 0x1C, SIGQUIT }
});

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


    const auto pkt = net::shell_message {net::packet_type::STDIN, std::vector(net::c_confirm_magic, net::c_confirm_magic + sizeof(net::c_confirm_magic)) };
    const auto words = serial::packet_serializer::serialize(pkt);
    const auto encrypted = cipher.encrypt(net::capnp_array_to_span(words));
    if (!encrypted) [[unlikely]] {
        spdlog::critical("Failed to confirm connection establishment: {}", encrypted.error());
        return EXIT_FAILURE;
    }
    if (!client->send(*encrypted)) {
        spdlog::critical("Failed to send encrypted confirmation.");
        return EXIT_FAILURE;
    }

    auto conf = client->recv();
    auto j = 0;
    while (!conf && j++ < 1'000) {
        conf = client->recv(&cipher);
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    if (!conf) [[unlikely]] {
        spdlog::critical("Failed to receive confirmation: {}", conf.error());
        return EXIT_FAILURE;
    }

    const auto confirm_msg = std::get_if<net::shell_message>(&*conf);
    if (!confirm_msg || confirm_msg->type != net::packet_type::STDIN) [[unlikely]] {
        spdlog::critical("Failed to receive confirmation: No viable packet");
        return EXIT_FAILURE;
    }
    if (!net::is_confirm<crypto::side::CLIENT>(confirm_msg->bytes)) [[unlikely]] {
        spdlog::critical("Confirmation magic was corrupted or wrong.");
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
            auto pkt = client->recv(&cipher);

            if (!pkt) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            const auto *const g_pkt = std::get_if<net::shell_message>(&*pkt);
            if (!g_pkt || g_pkt->type != net::packet_type::STDIN) continue;

            if (!g_pkt->bytes.empty()) {
                write(STDOUT_FILENO, g_pkt->bytes.data(), g_pkt->bytes.size());
            }
        }
    });

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWINCH);

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        spdlog::error("Failed to block SIGWINCH");
        return EXIT_FAILURE;
    }

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) {
        spdlog::error("Failed to create signalfd");
        return EXIT_FAILURE;
    }
    std::array<char, 1024 * 4> buffer {};
    constexpr auto fds_size = 2;
    std::array<pollfd, fds_size> fds{};
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    fds[1].fd = sfd;
    fds[1].events = POLLIN;
    while (true) {
        if (auto ret = poll(fds.data(), fds_size, 1); ret < 0) [[unlikely]] {
            spdlog::error("Poll error: {}", ret);
            break;
        }

        if (fds[0].revents & POLLIN) {
            if (const auto n = read(STDIN_FILENO, buffer.data(), buffer.size()); n > 0) {
                if (n == 1) {
                    auto it = std::ranges::find_if(key_map, [b = buffer[0]] (const auto &p) {
                        return p.first == b;
                    });
                    if (it != key_map.end()) {
                        int sig = it->second;
                        if (const auto rfc = net::sig2name(sig)) {
                            const auto p = net::shell_message{net::packet_type::SIGNAL, std::vector<net::u8> {rfc->begin(), rfc->end()}};
                            const auto s = serial::packet_serializer::serialize(p);
                            auto enc = cipher.encrypt(net::capnp_array_to_span(s));
                            if (!enc) [[unlikely]] continue;
                            auto _ = client->send(*enc, 1);
                        }
                    }
                }
                if (n == 1 && buffer[0] == 0x04) {
                    term.disable_raw_mode();
                    spdlog::info("Ctrl+D pressed. Exiting client ...");
                    break;
                }
                const auto data = std::vector<net::u8>  {buffer.data(), buffer.data() + n};
                const auto p = net::shell_message{net::packet_type::STDIN, data};
                const auto s = serial::packet_serializer::serialize(p);
                const auto enc = cipher.encrypt(net::capnp_array_to_span(s));
                if (!enc) [[unlikely]] {
                    // spdlog::error("Failed to encrypt data: {}", enc.error());
                    continue;
                }
                if (!client->send(*enc)) {
                    // spdlog::error("Failed to send data.");
                }
            } else if (n == 0) break;
        }
        if (fds[1].revents & POLLIN) {
            signalfd_siginfo fdsi{};

            if (const auto s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo)); s != sizeof(signalfd_siginfo)) continue;
            if (fdsi.ssi_signo != SIGWINCH) continue;

            winsize ws{};
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) [[unlikely]] {
                spdlog::error("Failed to get window size");
                continue;
            }

            const auto p = net::resize_packet {ws};
            const auto s = serial::packet_serializer::serialize(p);
            auto enc = cipher.encrypt(net::capnp_array_to_span(s));
            if (!enc) [[unlikely]] continue;
            auto _ = client->send(*enc, 1);
        }
    }

    return EXIT_SUCCESS;
}
