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
    class client {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        static inline constinit int max_channels = 3;
        client() = delete;
        [[nodiscard]]
        static constexpr std::expected<std::shared_ptr<client>, std::string> create() noexcept;
        [[nodiscard]]
        constexpr bool connect(std::string_view /* address */, int /* port */) const noexcept;
        [[nodiscard]]
        constexpr bool send(const packet &pkt, u8 channel_id = 0,
                  u32 flags = ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE) const noexcept;
        [[nodiscard]]
        constexpr bool send(std::vector<u8> &&pkt, u8 channel_id = 0,
                            u32 flags = ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE) const noexcept;
        constexpr void service(int timeout = 1000) const noexcept;
        explicit constexpr client(host && /* client host */) noexcept;
        constexpr void disconnect() const noexcept;
        constexpr void shutdown() noexcept;
    private:
        host m_host;
        bool m_running = true;
    };
    constexpr std::expected<std::shared_ptr<client>, std::string> client::create() noexcept {
        auto client_host = host{enet_host_create(nullptr /* create a client host */,
                                      1 /* only allow 1 outgoing connection */,
                                      max_channels /* allow up to `max_channels` channels to be used */,
                                      0 /* assume any amount of incoming bandwidth */,
                                      0 /* assume any amount of outgoing bandwidth */),
                     host_deleter{}};
        if (!client_host) {
            return std::unexpected{"Failed to create client."};
        }
        return std::make_shared<client>(std::move(client_host));
    }
    constexpr bool client::connect(const std::string_view addr, const int port) const noexcept {
        if (!m_host) return false;
        ENetAddress address{};
        enet_address_set_host(&address, addr.data());
        address.port = port;
        if (!enet_host_connect(m_host.get(), &address, 2, 0)) {
            return false;
        }
        return true;
    }
    constexpr bool client::send(const packet &pkt, const u8 channel_id, const u32 flags) const noexcept {
        if (!m_host) return false;
        const auto buf = serial::packet_serializer::serialize_into_pool(pkt);
        const auto p = enet_packet_create(buf->data(), buf->size(), flags);
        if (!p) [[unlikely]] return false;
        enet_peer_send(&m_host->peers[0], channel_id, p);
        enet_host_flush(m_host.get());
        return true;
    }
    constexpr bool client::send(std::vector<u8> &&pkt, const u8 channel_id, const u32 flags) const noexcept {
        if (!m_host) return false;
        const auto p = enet_packet_create(pkt.data(), pkt.size(), flags);
        if (!p) return false;
        enet_peer_send(&m_host->peers[0], channel_id, p);
        enet_host_flush(m_host.get());
        return true;
    }
    constexpr void client::service(const int timeout) const noexcept {
        ENetEvent event;
        while (m_running) {
            if (const int res = enet_host_service(m_host.get(), &event, timeout); res <= 0) return;
        switch (event.type) {
            case ENET_EVENT_TYPE_CONNECT: {
                if (!event.peer) [[unlikely]] return;
                event_bus_t::instance().create_enqueue(event.peer);
                return;
            }
            case ENET_EVENT_TYPE_DISCONNECT:
            case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
                if (!event.peer) [[unlikely]] return;
                event_bus_t::instance().create_enqueue(event.peer, event.data);
                return;
            }
            case ENET_EVENT_TYPE_RECEIVE: {
                if (!event.peer) [[unlikely]] return;
                if (!event.packet) [[unlikely]] return;
                event_bus_t::instance().create_enqueue(event.channelID, event.peer, event.packet);
                return;
            }
            default: return;
        }
    }
    }
    constexpr client::client(host &&client) noexcept :
        m_host(std::forward<host>(client)) {}
    constexpr void client::disconnect() const noexcept {
        if (!m_host || !m_host->peers)
            return;
        enet_peer_disconnect(&m_host->peers[0], 0);
    }
    constexpr void client::shutdown() noexcept {
        m_running = false;
    }
} // net
#endif //CLIENT_H
