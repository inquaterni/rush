//
// Created by inquaterni on 1/14/26.
//

#ifndef SERVER_H
#define SERVER_H
#include <expected>
#include <memory>
#include <string>
#include <variant>


#include "concurrentqueue.h"
#include "event.h"
#include "guard.h"
#include "host_deleter.h"
#include "object_pool.h"
#include "packet.h"
#include "packet_serializer.h"
#if defined(TESTING)
    #define RUSH_TEST_VIRTUAL virtual
#else
    #define RUSH_TEST_VIRTUAL
#endif

namespace net {
    struct packet_data_ {
        object_pool_t::pool_ptr data {nullptr, [] (object_pool_t::pointer) {}};
        ENetPeer *peer {nullptr};
        u32 flags{};
        u8 channel{};

        packet_data_(object_pool_t::pool_ptr data, ENetPeer *peer, const u32 flags, const u8 channel) noexcept :
            data(std::move(data)), peer(peer), flags(flags), channel(channel) {}

        packet_data_() = default;
    };

    struct disconnect {
        ENetPeer *peer {nullptr};
        u32 data;

        explicit disconnect(ENetPeer *peer, const u32 data = 0) noexcept
        : peer(peer), data(data) {}
    };

    using packet_data = std::variant<packet_data_, disconnect>;

    class host {
    public:
        using host_type = std::unique_ptr<ENetHost, host_deleter>;
        static constinit inline short max_clients = 32;
        static constinit inline short max_channels = 3;
#if defined(TESTING)
        virtual ~host() = default;
#endif
        explicit constexpr host(host_type && /* host */) noexcept;

        constexpr static std::expected<std::shared_ptr<host>, std::string>
        create(in6_addr /* address */, int /* port */) noexcept;
        [[nodiscard]]
        constexpr std::expected<event, std::string> service(int timeout = 1000) noexcept;
        RUSH_TEST_VIRTUAL constexpr bool send(ENetPeer *peer, const packet &pkt, u8 channel_id = 0,
                            u32 flags = ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE) noexcept;
        RUSH_TEST_VIRTUAL constexpr bool send(ENetPeer *peer, std::unique_ptr<std::vector<u8>, void (*)(std::vector<u8> *)> &&data, u8 channel_id = 0,
             u32 flags = ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE) noexcept;
        RUSH_TEST_VIRTUAL constexpr void disconnect(ENetPeer *peer) noexcept;
        constexpr void send_loop() noexcept;
        constexpr void shutdown() noexcept;
        constexpr int enet_host_service_locked(ENetHost *host, ENetEvent *event, enet_uint32 timeout);

    protected:
        moodycamel::ConcurrentQueue<packet_data> m_packets {};
        std::mutex m_mutex {};
        host_type m_host;
        std::atomic_bool m_running = true;
    };

    constexpr host::host(host_type &&host) noexcept
    : m_host(std::forward<host_type>(host)) {}
    constexpr std::expected<std::shared_ptr<host>, std::string> host::create(const in6_addr addr, const int port) noexcept {
        if (!guard::is_initialized())
            return std::unexpected{"ENet is not initialized."};

        ENetAddress address {};
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

        return std::make_shared<host>(std::move(server_host));
    }
    constexpr std::expected<event, std::string> host::service(const int timeout) noexcept {
        ENetEvent event;
        while (m_running) {
            if (const int res = enet_host_service_locked(m_host.get(), &event, timeout); res <= 0) return std::unexpected {"No event received."};
            switch (event.type) {
                case ENET_EVENT_TYPE_CONNECT: {
                    if (!event.peer) [[unlikely]]
                        return std::unexpected{"Peer is NULL."};
                    return connect_event::create(event.peer);
                }
                case ENET_EVENT_TYPE_DISCONNECT:
                case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
                    if (!event.peer) [[unlikely]]
                        return std::unexpected{"Peer is NULL."};
                    return disconnect_event::create(event.peer, event.data);
                }
                case ENET_EVENT_TYPE_RECEIVE: {
                    if (!event.peer) [[unlikely]]
                        return std::unexpected{"Peer is NULL."};
                    if (!event.packet) [[unlikely]]
                        return std::unexpected{"Packet is NULL."};
                    return receive_event::create(event.channelID, event.peer, event.packet);
                }
                default: std::unexpected{"No event received."};
            }
        }
        return std::unexpected{"Host has been stopped."};
    }
    constexpr bool host::send(ENetPeer *peer, const packet &pkt, const u8 channel_id, const u32 flags) noexcept {
        return m_packets.try_enqueue(packet_data_ {
            serial::packet_serializer::serialize_into_pool(pkt),
            peer,
            flags,
            channel_id,
        });
    }
    constexpr bool host::send(ENetPeer *peer, object_pool_t::pool_ptr &&data, const u8 channel_id, const u32 flags) noexcept {
        return m_packets.try_enqueue(packet_data_ {
            std::move(data),
            peer,
            flags,
            channel_id,
        });
    }
    constexpr void host::disconnect(ENetPeer *peer) noexcept {
        struct disconnect pkt{peer};
        m_packets.try_enqueue(pkt);
    }
    constexpr void host::send_loop() noexcept {
        packet_data pkt_data;
        while (m_running) {
            if (!m_packets.try_dequeue(pkt_data)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(16));
                continue;
            }
            std::visit(overloaded {
                [&] (packet_data_ &data) constexpr {
                    if (data.peer && data.peer->state == ENET_PEER_STATE_CONNECTED) {
                        {
                            std::scoped_lock lock(m_mutex);
                            if (const auto pkt = enet_packet_create(data.data->data(), data.data->size(), data.flags)) {
                                pkt->userData = data.data.release();
                                pkt->freeCallback = [](void* packet) {
                                    auto* user_data = static_cast<ENetPacket*>(packet)->userData;
                                    auto* vec = static_cast<std::vector<u8>*>(user_data);
                                    object_pool_t::get_instance().release(vec);
                                };
                                enet_peer_send(data.peer, data.channel, pkt);
                                enet_host_flush(m_host.get());
                            }
                        }
                    }
                },
                // ReSharper disable once CppParameterMayBeConstPtrOrRef
                [&] (struct disconnect &data) constexpr {
                    if (data.peer && data.peer->state == ENET_PEER_STATE_CONNECTED) {
                        {
                            std::scoped_lock lock(m_mutex);
                            enet_peer_disconnect(data.peer, data.data);
                            enet_host_flush(m_host.get());
                        }
                    }
                }
            }, pkt_data);
        }
    }
    constexpr void host::shutdown() noexcept { m_running = false; }
    constexpr int host::enet_host_service_locked(ENetHost *host, ENetEvent *event, enet_uint32 timeout) {
        std::unique_lock lock(m_mutex);
        enet_uint32 waitCondition;

        if (event != nullptr) {
            event->type   = ENET_EVENT_TYPE_NONE;
            event->peer   = nullptr;
            event->packet = nullptr;

            switch (enet_protocol_dispatch_incoming_commands(host, event)) {
                case 1:
                    return 1;

                case -1:
                    #ifdef ENET_DEBUG
                    perror("Error dispatching incoming packets");
                    #endif

                    return -1;

                default:
                    break;
            }
        }

        host->serviceTime = enet_time_get();
        timeout += host->serviceTime;

        do {
            if (ENET_TIME_DIFFERENCE(host->serviceTime, host->bandwidthThrottleEpoch) >= ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL) {
                enet_host_bandwidth_throttle(host);
            }

            switch (enet_protocol_send_outgoing_commands(host, event, 1)) {
                case 1:
                    return 1;

                case -1:
                    #ifdef ENET_DEBUG
                    perror("Error sending outgoing packets");
                    #endif

                    return -1;

                default:
                    break;
            }

            switch (enet_protocol_receive_incoming_commands(host, event)) {
                case 1:
                    return 1;

                case -1:
                    #ifdef ENET_DEBUG
                    perror("Error receiving incoming packets");
                    #endif

                    return -1;

                default:
                    break;
            }

            switch (enet_protocol_send_outgoing_commands(host, event, 1)) {
                case 1:
                    return 1;

                case -1:
                    #ifdef ENET_DEBUG
                    perror("Error sending outgoing packets");
                    #endif

                    return -1;

                default:
                    break;
            }

            if (event != nullptr) {
                switch (enet_protocol_dispatch_incoming_commands(host, event)) {
                    case 1:
                        return 1;

                    case -1:
                        #ifdef ENET_DEBUG
                        perror("Error dispatching incoming packets");
                        #endif

                        return -1;

                    default:
                        break;
                }
            }

            if (ENET_TIME_GREATER_EQUAL(host->serviceTime, timeout)) {
                return 0;
            }

            do {
                host->serviceTime = enet_time_get();

                if (ENET_TIME_GREATER_EQUAL(host->serviceTime, timeout)) {
                    return 0;
                }

                waitCondition = ENET_SOCKET_WAIT_RECEIVE | ENET_SOCKET_WAIT_INTERRUPT;
                lock.unlock();
                if (enet_socket_wait(host->socket, &waitCondition, ENET_TIME_DIFFERENCE(timeout, host->serviceTime)) != 0) {
                    return -1;
                }
                lock.lock();
            } while (waitCondition & ENET_SOCKET_WAIT_INTERRUPT);

            host->serviceTime = enet_time_get();
        } while (waitCondition & ENET_SOCKET_WAIT_RECEIVE);

        return 0;
    }

} // net

#endif //SERVER_H
