//
// Created by inquaterni on 12/30/25.
//
#include "../client/guard.h"
#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "cipher.h"
#include "host.h"
#include "key_pair.h"
#include "packet.h"
#include "state.h"
#include "xchacha20poly1305.h"
#include <asio.hpp>

#include "spdlog/spdlog.h"

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    net::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    crypto::guard::get_instance();

    auto io_ctx = asio::io_context {};
    asio::signal_set signals(io_ctx, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto){ io_ctx.stop(); });

    auto server = net::host::create(ENET_HOST_ANY, 6969, io_ctx);
    if (!server) {
        spdlog::critical("Failed to create server: {}", server.error());
        return EXIT_FAILURE;
    }
    auto keys = crypto::key_pair::enroll();
    if (!keys) {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }
    server.value()->service(16);
    spdlog::info("Server is initialized");

    asio::steady_timer timer(io_ctx);

    std::function<void()> app_tick = [&] {
        auto e = (*server)->recv();
        if (!e) {
            timer.expires_after(std::chrono::milliseconds(16));
            timer.async_wait([&](const std::error_code ec) {
                if (!ec) app_tick();
            });
            return;
        }

        const std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();
        std::visit<void>(
            net::overloaded{[&](const net::connect_event &ce) constexpr {
                auto session = pty::session::create("/bin/fish");
                if (!session) [[unlikely]] {
                    spdlog::critical("Failed to create pty session: {}", session.error());
                    return;
                }
                ce.peer()->data = static_cast<void *>(
                        new net::peer_context{*server, net::handshake{*keys}, std::move(*session)});
            },
            [&](net::receive_event &re) constexpr {
                const auto ctx = static_cast<net::peer_context *>(re.peer()->data);
                ctx->handle(re);
            },
            [&](net::disconnect_event &de) constexpr {
                if (const auto ctx = static_cast<net::peer_context *>(de.peer()->data); ctx) {
                    delete ctx;
                    de.set_peer(nullptr);
                }
            }}, e.value());

        const auto duration = std::chrono::high_resolution_clock::now() - begin;
        spdlog::info("Event handling time: {}μs",
                     std::chrono::duration_cast<std::chrono::microseconds>(duration).count());

        asio::post(io_ctx, app_tick);
    };
    asio::post(io_ctx, app_tick);

    io_ctx.run();
    return EXIT_SUCCESS;
}
