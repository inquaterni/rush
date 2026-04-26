// Copyright (c) 2026 Maksym Matskevych
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#include <iostream>
#include <spdlog/spdlog.h>
#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "cipher.h"
#include "client.h"
#include "guard.h"
#include "key_pair.h"
#include "signals.hpp"
#include "xchacha20poly1305.h"
#include <sys/signalfd.h>
// #include "asio/co_spawn.hpp"
// #include "asio/signal_set.hpp"
#include <asio/co_spawn.hpp>
#include <asio/signal_set.hpp>
#include "state.h"
#include "global.h"
#if RUSH_EXCEPTIONS_ENABLED
#else
namespace asio::detail {
    template <typename Exception>
    void throw_exception(const Exception& e) {
        std::cerr << "[ASIO FATAL ERROR] " << e.what() << '\n';
        std::abort();
    }
    template void throw_exception<asio::execution::bad_executor>(asio::execution::bad_executor const&);
    template void throw_exception<asio::invalid_service_owner>(asio::invalid_service_owner const&);
    template void throw_exception<std::logic_error>(std::logic_error const&);
    template void throw_exception<std::system_error>(std::system_error const&);
    template void throw_exception<std::out_of_range>(std::out_of_range const&);
    template void throw_exception<std::bad_alloc>(std::bad_alloc const&);
    template void throw_exception<asio::service_already_exists>(asio::service_already_exists const&);
} // asio::detail
#endif
constexpr std::pair<std::string_view, std::string_view>
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
    auto exp_client = net::client::create();
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
    if (!client->connect(host, 6969)) {
        spdlog::critical("Failed to connect to server. Is server running?");
        return EXIT_FAILURE;
    }
    auto& bus = net::event_bus_t::instance();
    std::unique_ptr<net::client_context> ctx {nullptr};
    auto work_guard = asio::make_work_guard(io_ctx);
    std::jthread pump_thread {[&io_ctx] {
        io_ctx.run();
    }};
    std::function<void(std::error_code, int)> sig_handler;
    sig_handler = [&](const std::error_code ec, const int signo) {
        if (ec) return;
        if (signo == SIGINT || signo == SIGTERM || signo == SIGQUIT) {
            client->disconnect();
            io_ctx.stop();
            std::exit(1);
        }
        signals.async_wait(sig_handler);
    };
    signals.async_wait(sig_handler);
    while (true) {
        client->service(100);
        if (term.pwd_active()) [[unlikely]] {
            if (auto pwd = term.poll_pwd()) {
                if (!bus.enqueue(net::pwd_response_event(std::move(*pwd)))) {
                    spdlog::error("Failed to send password.");
                }
            }
        }
        auto e = bus.dequeue();
        if (!e) {
            continue;
        }
        const auto ec = std::visit<std::optional<asio::error_code>>(net::overloaded{
            [&](const net::connect_event &) constexpr {
                spdlog::info("Connected. Sending handshake...");
                if (!client->send(net::handshake_packet{keys->cpublic_key()})) [[unlikely]] {
                    spdlog::error("Failed to send handshake.");
                    return std::nullopt;
                }
                ctx = std::make_unique<net::client_context>(client, net::handshake{}, *keys, io_ctx, user, signals);
                return std::nullopt;
            },
            [&](net::receive_event &) constexpr {
                ctx->handle(*e);
                return std::nullopt;
            },
            [&](net::disconnect_event &) constexpr {
                if (term.is_raw()) term.disable_raw_mode();
                if (ctx) spdlog::info("Disconnected.");
                else spdlog::info("Could not connect to remote address.");
                ctx.reset();
                io_ctx.stop();
                pump_thread.join();
                client->shutdown();
                return asio::error::operation_aborted;
            },
            [&](net::pwd_request_event &) constexpr {
                term.begin_pwd(std::format("{}'s password: ", user_host));
                return std::nullopt;
            },
            [&](net::pwd_response_event &) constexpr {
                ctx->handle(*e);
                return std::nullopt;
            }
        }, *e);
        if (ec) break;
    }
    return EXIT_SUCCESS;
}
