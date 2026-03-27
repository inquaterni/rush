//
// Created by inquaterni on 12/30/25.
//
#include <asio.hpp>
#include "../client/guard.h"
#include "../crypto/include/guard.h"
#include "../net/include/guard.h"
#include "../net/include/host.h"
#include "key_pair.h"
#include "packet.h"
#include "state.h"

#include "global.h"
#include "spdlog/spdlog.h"

#if RUSH_EXCEPTIONS_ENABLED
#else
namespace asio::detail {
    template<typename Exception>
    void throw_exception(const Exception &e) {
        std::cerr << "[ASIO FATAL ERROR] " << e.what() << '\n';
        std::abort();
    }
    template void throw_exception<asio::execution::bad_executor>(asio::execution::bad_executor const &);
    template void throw_exception<asio::invalid_service_owner>(asio::invalid_service_owner const &);
    template void throw_exception<std::logic_error>(std::logic_error const &);
    template void throw_exception<std::system_error>(std::system_error const &);
    template void throw_exception<std::out_of_range>(std::out_of_range const &);
    template void throw_exception<std::bad_alloc>(std::bad_alloc const &);
    template void throw_exception<asio::service_already_exists>(asio::service_already_exists const &);

} // namespace asio::detail
#endif

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    net::guard::get_instance();
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    crypto::guard::get_instance();

    auto io_ctx = asio::io_context{};

    auto host = net::host::create(ENET_HOST_ANY, 6969);
    if (!host) {
        spdlog::critical("Failed to create server: {}", host.error());
        return EXIT_FAILURE;
    }
    auto keys = crypto::keys_factory::enroll_key_pair();
    if (!keys) {
        spdlog::critical("Failed to enroll key pair: {}", keys.error());
        return EXIT_FAILURE;
    }
    spdlog::info("Server is initialized");

    std::atomic_bool shutdown = false;

    std::jthread send_thread{[&host] { (*host)->send_loop(); }};
    auto work_guard = asio::make_work_guard(io_ctx);
    std::jthread pump_thread{[&io_ctx] { io_ctx.run(); }};

    asio::signal_set signals(io_ctx, SIGINT, SIGTERM);
    signals.async_wait([&io_ctx, &host, &work_guard, &shutdown](auto error, int) {
        if (!error) {
            (*host)->shutdown();
            work_guard.reset();
            io_ctx.stop();
            shutdown = true;
        }
    });
    while (!shutdown) {
        auto e = (*host)->service();
        if (!e) {
            continue;
        }

        std::visit(net::overloaded{[&](const net::connect_event &ce) constexpr {
           spdlog::info("Peer connected. Waiting for handshake.");
           ce.peer()->data = static_cast<void *>( new net::peer_context{*host, net::handshake{}, *keys, io_ctx});
        },
       [&](net::receive_event &re) constexpr {
           const auto ctx = static_cast<net::peer_context *>(re.peer()->data);
           ctx->handle(re);
       },
       [&](net::disconnect_event &de) constexpr {
           if (const auto ctx = static_cast<net::peer_context *>(de.peer()->data); ctx) {
               spdlog::info("Peer {} disconnected.", static_cast<void *>(ctx));
               delete ctx;
               de.set_peer(nullptr);
           }
       }},
       e.value());
    }

    pump_thread.join();
    send_thread.join();
    return EXIT_SUCCESS;
}
