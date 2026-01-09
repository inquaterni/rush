//
// Created by inquaterni on 12/30/25.
//

#ifndef SERVER_H
#define SERVER_H
#include <expected>
#include <memory>
#include <spdlog/spdlog.h>

#include "../serial/include/packet_serializer.h"
#include "guard.h"
#include "host_deleter.h"
#include "packet.h"
#include "peer_deleter.h"
#include "secure_session.h"

namespace net {
    class server final {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        using peer = std::unique_ptr<ENetPeer, peer_deleter>;
        // using secure_session_ptr = std::unique_ptr<crypto::secure_session>;
        static constexpr short max_clients = 1;

        server() = delete;

        [[nodiscard]]
        constexpr static std::expected<server, std::string> create(in6_addr /* address */, int /* port */) noexcept;
        template<class Tp>
        bool send(const Tp &packet, u8 channel_id = 0, u32 flags = ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE) noexcept;
        // constexpr static std::expected<server, std::string> create(in6_addr /* address */, int /* port */,
        //     secure_session_ptr && /* session */) noexcept;
        template<typename Tp>
        [[nodiscard]]
        std::expected<Tp, std::string> recv(int timeout = 1000) noexcept;

        // constexpr bool use_session(secure_session_ptr && /* session */) noexcept;

    private:
        host server_;
        peer client;
        // secure_session_ptr secure_session = nullptr;

        explicit constexpr server(host && /* server host */) noexcept;
        // explicit constexpr server(host && /* server host */, secure_session_ptr && /* session */) noexcept;
    };

    constexpr server::server(host &&s) noexcept : server_{std::forward<host>(s)} {}
    // constexpr server::server(host &&h, secure_session_ptr &&s) noexcept
    // : server_{std::forward<host>(h)}, secure_session(std::exchange(s, nullptr)) {}

    constexpr std::expected<server, std::string> server::create(const in6_addr addr, const int port) noexcept {
        if (!guard::is_initialized()) [[unlikely]] {
            return std::unexpected("ENet context is not initialized.");
        }

        ENetAddress address{};
        address.host = addr;
        address.port = port;

        auto server_host = host{enet_host_create(&address /* the address to bind the server host to */,
                                                 max_clients /* allow up to 32 clients and/or outgoing connections */,
                                                 2 /* allow up to 2 channels to be used, 0 and 1 */,
                                                 0 /* assume any amount of incoming bandwidth */,
                                                 0 /* assume any amount of outgoing bandwidth */),
                                net::host_deleter{}};

        if (!server_host) {
            return std::unexpected("An error occurred while trying to create an ENet server host.\n");
        }

        return server{std::move(server_host)};
    }
    // constexpr std::expected<server, std::string> server::create(const in6_addr addr, const int port,
    //                                                             secure_session_ptr &&session) noexcept {
    //     if (!guard::is_initialized()) [[unlikely]] {
    //         return std::unexpected("ENet context is not initialized.");
    //     }
    //
    //     ENetAddress address{};
    //     address.host = addr;
    //     address.port = port;
    //
    //     auto server_host = host{enet_host_create(&address /* the address to bind the server host to */,
    //                                              max_clients /* allow up to 32 clients and/or outgoing connections */,
    //                                              2 /* allow up to 2 channels to be used, 0 and 1 */,
    //                                              0 /* assume any amount of incoming bandwidth */,
    //                                              0 /* assume any amount of outgoing bandwidth */),
    //                             net::host_deleter{}};
    //
    //     if (!server_host) {
    //         return std::unexpected("An error occurred while trying to create an ENet server host.\n");
    //     }
    //
    //     return server{std::move(server_host), std::forward<secure_session_ptr>(session)};
    // }
    // constexpr bool server::use_session(secure_session_ptr &&session) noexcept {
    //     if (!session) return false;
    //     secure_session = std::exchange(session, nullptr);
    //     return true;
    // }

    template<typename Tp>
    bool server::send(const Tp &packet, const u8 channel_id, const u32 flags) noexcept {
        if (!client) {
            return false;
        }
        const auto bytes = serial::packet_serializer::serialize(packet);
        if (!bytes) {
            return false;
        }
        const auto p = enet_packet_create(bytes->asBytes().begin(), bytes->size() * sizeof(capnp::word), flags);

        if (!p) {
            return false;
        }
        enet_peer_send(client.get(), channel_id, p);
        enet_host_flush(server_.get());

        return true;
    }
    template<typename Tp>
    std::expected<Tp, std::string> server::recv(const int timeout) noexcept {
        ENetEvent event;
        while (enet_host_service(server_.get(), &event, timeout) > 0) {
            switch (event.type) {
                case ENET_EVENT_TYPE_CONNECT: {
                    if (event.peer) {
                        spdlog::info("Client connected.");
                        client = peer {event.peer, peer_deleter {}};
                    }
                } break;
                case ENET_EVENT_TYPE_RECEIVE: {
                    if (event.packet) {
                        const auto word_ptr = reinterpret_cast<const capnp::word *>(event.packet->data);
                        const std::size_t word_size = event.packet->dataLength / sizeof(capnp::word);
                        return serial::packet_serializer::deserialize<Tp>(std::span {word_ptr, word_size});
                    }
                } break;
                case ENET_EVENT_TYPE_DISCONNECT: {
                    spdlog::info("Client disconnected.");
                    client = nullptr;
                };
                default: break;
            }
        }

        return std::unexpected {"Failed to receive packet."};
    }
} // namespace enet


#endif // SERVER_H
