//
// Created by inquaterni on 12/30/25.
//
#include <iostream>
#include <spdlog/spdlog.h>

#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "guard.h"
#include "cipher.h"
#include "client.h"
#include "key_pair.h"
#include "keys_factory.h"
#include "signals.hpp"
#include "xchacha20poly1305.h"

#include <sys/signalfd.h>

#include "asio/as_tuple.hpp"
#include "asio/co_spawn.hpp"
#include "asio/detached.hpp"
#include "asio/signal_set.hpp"
#include "state.h"


std::pair<std::string_view, std::string_view>
split_pair(std::string_view arg, const char delimiter) {

    const auto pos = arg.find(delimiter);
    if (pos == std::string_view::npos) {
        return {arg, {}};
    }

    return {
        arg.substr(0, pos),
        arg.substr(pos + 1)
    };
}

int main(const int argc, char **argv) {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    net::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    crypto::guard::get_instance();

    constexpr int poll_timeout_ms = 1;

    auto io_ctx = asio::io_context {};
    asio::signal_set signals(io_ctx);
    signals.add(SIGHUP);
    signals.add(SIGINT);
    signals.add(SIGQUIT);
    signals.add(SIGTERM);
    signals.add(SIGUSR1);
    signals.add(SIGUSR2);
    signals.add(SIGWINCH);

    if (argc < 2) {
        spdlog::error("No `<user>@<host>` argument.");
        return EXIT_FAILURE;
    }

    const std::string_view user_host = argv[1];
    const auto [user, host] = split_pair(user_host, '@');

    auto exp_client = net::client::create(io_ctx);
    if (!exp_client) [[unlikely]] {
        spdlog::critical("Failed to create client: {}", exp_client.error());
        return EXIT_FAILURE;
    }
    auto client = *exp_client;
    auto keys = crypto::key_pair::enroll();
    if (!keys) [[unlikely]] {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }
    auto &term = term::guard::get_instance();

    client->service(poll_timeout_ms);

    if (!client->connect(host, 6969)) {
        spdlog::critical("Failed to connect to server. Is server running?");
        return EXIT_FAILURE;
    }


    spdlog::info("Connected. Sending handshake...");

    asio::steady_timer timer(io_ctx);

    std::unique_ptr<net::client_context> ctx {nullptr};
    asio::co_spawn(io_ctx, [poll_timeout_ms, user, &timer, &client, &keys, &io_ctx, &ctx, &signals, &term] () -> asio::awaitable<void> {
        while (true) {
            auto e = client->recv();
            if (!e) {
                timer.expires_after(std::chrono::milliseconds(poll_timeout_ms));
                if (const auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable)); ec) {
                    co_return;
                }
                continue;
            }

            const auto ec = std::visit<std::optional<asio::error_code>>(net::overloaded{
                [&](const net::connect_event &) constexpr {
                    if (!client->send(net::handshake_packet{keys->cpublic_key()})) [[unlikely]] {
                        spdlog::error("Failed to send handshake.");
                        return std::nullopt;
                    }
                    ctx = std::make_unique<net::client_context>(client, net::handshake{}, *keys, io_ctx, user, signals);
                    return std::nullopt;
                },
                [&](net::receive_event &re) constexpr {
                    ctx->handle(re);
                    return std::nullopt;
                },
                [&](net::disconnect_event &) constexpr {
                    if (term.is_raw()) term.disable_raw_mode();
                    spdlog::info("Disconnected.");
                    ctx.reset();
                    io_ctx.stop();
                    return asio::error::operation_aborted;
                }
            }, e.value());

            if (ec) co_return;
            co_await asio::post(asio::use_awaitable);
        }
    }, asio::detached);

    io_ctx.run();
    return EXIT_SUCCESS;
}
