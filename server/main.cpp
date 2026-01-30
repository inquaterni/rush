//
// Created by inquaterni on 12/30/25.
//
#include <asio.hpp>
#include "../client/guard.h"
#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "../net/include/host.h"
#include "cipher.h"
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

    constexpr int poll_timeout_ms = 1;

    auto io_ctx = asio::io_context {};
    asio::signal_set signals(io_ctx, SIGINT, SIGTERM);
    signals.async_wait([&io_ctx](auto, auto){ io_ctx.stop(); });

    auto host = net::host::create(ENET_HOST_ANY, 6969, io_ctx);
    if (!host) {
        spdlog::critical("Failed to create server: {}", host.error());
        return EXIT_FAILURE;
    }
    auto keys = crypto::key_pair::enroll();
    if (!keys) {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }
    (*host)->service(poll_timeout_ms);
    spdlog::info("Server is initialized");

    asio::steady_timer timer(io_ctx);

    asio::co_spawn(io_ctx, [poll_timeout_ms, &timer, &host, &keys, &io_ctx] () -> asio::awaitable<void> {
        while (true) {
            auto e = (*host)->recv();
            if (!e) {
                timer.expires_after(std::chrono::milliseconds(poll_timeout_ms));
                if (const auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable)); ec) {
                    co_return;
                }
                continue;
            }

            std::visit(net::overloaded{
                [&](const net::connect_event &ce) constexpr {
                    ce.peer()->data = static_cast<void *>(new net::peer_context{*host, net::handshake{}, *keys, io_ctx});
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

            co_await asio::post(asio::use_awaitable);
        }
    }, asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}
