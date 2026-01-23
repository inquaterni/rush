//
// Created by inquaterni on 1/14/26.
//

#ifndef SERVER_H
#define SERVER_H
#include <asio/detail/descriptor_ops.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <expected>
#include <memory>
#include <string>
#include <variant>


#include "concurrentqueue.h"
#include "event.h"
#include "guard.h"
#include "host_deleter.h"
#include "packet.h"
#include "packet_serializer.h"

namespace net {
    class host: public std::enable_shared_from_this<host> {
    public:
        using host_type = std::unique_ptr<ENetHost, host_deleter>;
        static constinit inline short max_clients = 32;
        static constinit inline short max_channels = 3;

        explicit constexpr host(host_type && /* host */, asio::io_context & /* ctx */) noexcept;

        constexpr static std::expected<std::shared_ptr<host>, std::string>
        create(in6_addr /* address */, int /* port */, asio::io_context & /* ctx */) noexcept;
        constexpr void service(int timeout = 16) noexcept;
        constexpr void do_service_step(int timeout, const std::error_code &ec) noexcept;
        constexpr std::expected<event, std::string> recv() noexcept;
        constexpr bool send(ENetPeer *peer, const packet &pkt, u8 channel_id = 0,
                            u32 flags = ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE,
                            bool flush = true) const;
        constexpr bool send(ENetPeer *peer, std::span<const u8> data, u8 channel_id = 0,
            u32 flags = ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE,
            bool flush = true) const;
        constexpr bool send(ENetPeer *peer, const std::vector<u8> &data, u8 channel_id = 0,
            u32 flags = ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE,
            bool flush = true) const;
        constexpr void disconnect(ENetPeer *peer) const noexcept;

    private:
        host_type m_host;
        mutable std::mutex m_mutex{};
        asio::steady_timer m_timer;
        asio::io_context &m_ctx;
        moodycamel::ConcurrentQueue<ENetEvent> event_queue;
    };

    constexpr host::host(host_type &&host, asio::io_context &ctx) noexcept
    : m_host(std::forward<host_type>(host)), m_timer(ctx), m_ctx(ctx) {}
    constexpr std::expected<std::shared_ptr<host>, std::string> host::create(const in6_addr addr, const int port,
                                                                             asio::io_context &ctx) noexcept {
        if (!guard::is_initialized())
            return std::unexpected{"ENet is not initialized."};

        ENetAddress address;
        address.host = addr;
        address.port = port;

        auto server_host = host_type{
                enet_host_create(&address /* the address to bind the server host to */,
                                 max_clients /* allow up to `max_clients` clients and/or outgoing connections */,
                                 max_channels /* allow up to `max_channels` channels to be used, starting from 0 */,
                                 0 /* assume any amount of incoming bandwidth */,
                                 0 /* assume any amount of outgoing bandwidth */
                                 ),
                host_deleter{}};
        if (!server_host) {
            return std::unexpected{
                    "An error occurred while trying to create an ENet server host. Is this host occupied?"};
        }

        return std::make_shared<host>(std::move(server_host), ctx);
    }
    constexpr void host::service(const int timeout) noexcept {
        auto self = shared_from_this();
        m_timer.expires_after(std::chrono::milliseconds(0));
        m_timer.async_wait([self, timeout] (const std::error_code &ec) {
            self->do_service_step(timeout, ec);
        });
    }
    constexpr void host::do_service_step(const int timeout, const std::error_code &ec) noexcept {
        if (ec == asio::error::operation_aborted || !m_host) return;

        ENetEvent event;
        int service_result = 0;

        {
            std::scoped_lock lock(m_mutex);
            service_result = enet_host_service(m_host.get(), &event, timeout);
        }
        if (service_result > 0) {
            event_queue.enqueue(event);
        }
        auto self = shared_from_this();
        m_timer.expires_after(std::chrono::milliseconds(1));
        m_timer.async_wait([self, timeout](const std::error_code& ec_) {
            self->do_service_step(timeout, ec_);
        });
    }
    constexpr std::expected<event, std::string> host::recv() noexcept {
        ENetEvent event;
        if (!event_queue.try_dequeue(event)) {
            return std::unexpected{"No events found."};
        }

        switch (event.type) {
            case ENET_EVENT_TYPE_CONNECT: {
                return connect_event::create(event.peer);
            }
            case ENET_EVENT_TYPE_DISCONNECT:
            case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
                return disconnect_event::create(event.peer, event.data);
            }
            case ENET_EVENT_TYPE_RECEIVE: {
                return receive_event::create(event.channelID, event.peer, event.packet);
            }
            default:
                return std::unexpected{"No events found."};
        }
    }
    constexpr bool host::send(ENetPeer *peer, const packet &pkt, const u8 channel_id, const u32 flags,
                              const bool flush) const {
        std::scoped_lock lock {m_mutex};
        if (!m_host) [[unlikely]]
            return false;

        const auto words = serial::packet_serializer::serialize(pkt);

        const auto enet_pkt = enet_packet_create(words.begin(), words.size() * sizeof(capnp::word), flags);
        if (!enet_pkt) [[unlikely]] {
            return false;
        }
        enet_peer_send(peer, channel_id, enet_pkt);
        if (flush) [[likely]]
            enet_host_flush(m_host.get());

        return true;
    }
    constexpr bool host::send(ENetPeer *peer, const std::span<const u8> data, const u8 channel_id, const u32 flags,
                              const bool flush) const {
        std::scoped_lock lock{m_mutex};
        if (!m_host) [[unlikely]]
            return false;

        const auto enet_pkt = enet_packet_create(data.data(), data.size() * sizeof(u8), flags);
        if (!enet_pkt) [[unlikely]]
            return false;
        enet_peer_send(peer, channel_id, enet_pkt);
        if (flush) [[likely]]
            enet_host_flush(m_host.get());

        return true;
    }
    constexpr bool host::send(ENetPeer *peer, const std::vector<u8> &data, const u8 channel_id, const u32 flags,
                              const bool flush) const {
        std::scoped_lock lock{m_mutex};
        if (!m_host) [[unlikely]]
            return false;

        const auto enet_pkt = enet_packet_create(data.data(), data.size() * sizeof(u8), flags);
        if (!enet_pkt) [[unlikely]]
            return false;
        enet_peer_send(peer, channel_id, enet_pkt);
        if (flush) [[likely]]
            enet_host_flush(m_host.get());

        return true;
    }
    constexpr void host::disconnect(ENetPeer *peer) const noexcept {
        std::scoped_lock lock {m_mutex};
        if (!m_host || !peer)
            return;
        enet_peer_disconnect(peer, 0);
    }

} // net

#endif //SERVER_H
