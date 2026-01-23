//
// Created by inquaterni on 12/31/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include <expected>
#include <memory>
#include <spdlog/spdlog.h>
#include <utility>

#include "../cmake-build-debug/_deps/asio-src/asio/include/asio/io_context.hpp"
#include "../cmake-build-debug/_deps/asio-src/asio/include/asio/steady_timer.hpp"
#include "../net/include/host_deleter.h"
#include "../net/include/peer_deleter.h"
#include "cipher.h"
#include "concurrentqueue.h"
#include "event.h"
#include "packet.h"
#include "packet_serializer.h"

namespace net {
    class client: public std::enable_shared_from_this<client> {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        static inline constinit int max_channels = 3;
        client() = delete;

        [[nodiscard]]
        static constexpr std::expected<std::shared_ptr<client>, std::string> create(asio::io_context & /* context */) noexcept;

        constexpr bool connect(std::string_view /* address */, int /* port */) noexcept;
        [[nodiscard]]
        constexpr bool send(const packet &pkt, u8 channel_id = 0,
                  u32 flags = ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE) noexcept;
        [[nodiscard]]
        constexpr bool send(const std::vector<u8> &pkt, u8 channel_id = 0,
                  u32 flags = ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE) noexcept;
        constexpr void service(int timeout = 16) noexcept;
        constexpr void do_service_step(int /* timeout */, const std::error_code & /* ec */) noexcept;
        constexpr std::expected<event, std::string> recv() noexcept;
        constexpr client(host && /* client host */, asio::io_context & /* context */) noexcept;
        constexpr void disconnect() noexcept;

    private:
        host m_host;
        asio::io_context &io_ctx;
        asio::steady_timer m_timer;
        std::mutex mutex {};
        moodycamel::ConcurrentQueue<ENetEvent> events {};

    };

    constexpr std::expected<std::shared_ptr<client>, std::string> client::create(asio::io_context &ctx) noexcept {

        auto client_host = host{enet_host_create(nullptr /* create a client host */,
                                      1 /* only allow 1 outgoing connection */,
                                      max_channels /* allow up to `max_channels` channels to be used */,
                                      0 /* assume any amount of incoming bandwidth */,
                                      0 /* assume any amount of outgoing bandwidth */),
                     host_deleter{}};

        if (!client_host) {
            return std::unexpected{"Failed to create client."};
        }

        return std::make_shared<client>(std::move(client_host), ctx);
    }
    constexpr bool client::connect(const std::string_view addr, const int port) noexcept {
        std::scoped_lock lock{mutex};
        if (!m_host) return false;

        ENetAddress address{};

        enet_address_set_host(&address, addr.data());
        address.port = port;

        if (!enet_host_connect(m_host.get(), &address, 2, 0)) {
            return false;
        }

        return true;
    }
    constexpr bool client::send(const packet &pkt, const u8 channel_id, const u32 flags) noexcept {
        std::scoped_lock lock{mutex};
        if (!m_host) return false;

        const auto words = serial::packet_serializer::serialize(pkt);
        const auto p = enet_packet_create(words.asBytes().begin(), words.size() * sizeof(capnp::word), flags);
        if (!p) [[unlikely]] return false;

        enet_peer_send(&m_host->peers[0], channel_id, p);
        enet_host_flush(m_host.get());

        return true;
    }
    constexpr bool client::send(const std::vector<u8> &pkt, const u8 channel_id, const u32 flags) noexcept {
        std::scoped_lock lock{mutex};
        if (!m_host) return false;

        const auto p = enet_packet_create(pkt.data(), pkt.size(), flags);
        if (!p) return false;

        enet_peer_send(&m_host->peers[0], channel_id, p);
        enet_host_flush(m_host.get());

        return true;
    }
    constexpr void client::service(const int timeout) noexcept {
        auto self = shared_from_this();
        m_timer.expires_after(std::chrono::milliseconds(0));
        m_timer.async_wait([self, timeout](const std::error_code &ec) { self->do_service_step(timeout, ec); });
    }
    constexpr void client::do_service_step(int timeout, const std::error_code &ec) noexcept {
        if (ec == asio::error::operation_aborted) return;

        ENetEvent event;
        int service_result = 0;
        {
            std::scoped_lock lock{mutex};
            if (!m_host) return;
            service_result = enet_host_service(m_host.get(), &event, timeout);
        }
        if (service_result > 0) {
            events.enqueue(event);
        }
        auto self = shared_from_this();
        m_timer.expires_after(std::chrono::milliseconds(1));
        m_timer.async_wait([self, timeout](const std::error_code &ec_) { self->do_service_step(timeout, ec_); });
    }
    constexpr std::expected<event, std::string> client::recv() noexcept {
        ENetEvent event;
        if (!events.try_dequeue(event)) {
            return std::unexpected{"No events found."};
        }

        switch (event.type) {
            case ENET_EVENT_TYPE_CONNECT: {
                if (!event.peer) [[unlikely]] return std::unexpected{"Peer is NULL."};
                return connect_event::create(event.peer);
            }
            case ENET_EVENT_TYPE_DISCONNECT:
            case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
                if (!event.peer) [[unlikely]] return std::unexpected{"Peer is NULL."};
                return disconnect_event::create(event.peer, event.data);
            }
            case ENET_EVENT_TYPE_RECEIVE: {
                if (!event.peer) [[unlikely]] return std::unexpected{"Peer is NULL."};
                if (!event.packet) [[unlikely]] return std::unexpected{"Packet is NULL."};
                return receive_event::create(event.channelID, event.peer, event.packet);
            }
            default: assert(0 && "Unreachable");
        }
    }

    constexpr client::client(host &&client, asio::io_context &ctx) noexcept :
        m_host(std::forward<host>(client)), io_ctx(ctx), m_timer(ctx) {}
    constexpr void client::disconnect() noexcept {
        std::scoped_lock lock {mutex};
        if (!m_host || !m_host->peers)
            return;
        enet_peer_disconnect(&m_host->peers[0], 0);
    }
} // net



#endif //CLIENT_H
