//
// Created by inquaterni on 12/30/25.
//

#ifndef SERVER_H
#define SERVER_H
#include <expected>
#include <memory>
#include <spdlog/spdlog.h>

#include "host_deleter.h"
#include "packet.h"
#include "peer_deleter.h"

namespace enet {
    class peer_deleter;
    class server final {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        using peer = std::unique_ptr<ENetPeer, peer_deleter>;
        static constexpr short max_clients = 1;

        server() = delete;

        [[nodiscard]]
        static std::expected<server, std::string> create(in6_addr /* address */, int /* port */);

        template<typename Tp>
        bool send(const packet<Tp> & /* packet */, u8 channel_id = 0) noexcept;
        template<typename Tp>
        [[nodiscard]]
        std::expected<packet<Tp>, std::string> recv(int timeout = 1000) noexcept;

    private:
        host host_;
        peer client_;

        explicit server(host && /* server host */) noexcept;
    };
    template<typename Tp>
    bool server::send(const packet<Tp> &packet, const u8 channel_id) noexcept {
        if (!client_) {
            return false;
        }
        const auto enet_pack = packet.to_enet();
        if (!enet_pack) {
            return false;
        }

        enet_peer_send(client_.get(), channel_id, enet_pack.get());
        enet_host_flush(host_.get());
        return true;
    }
    template<typename Tp>
    std::expected<packet<Tp>, std::string> server::recv(const int timeout) noexcept {
        ENetEvent event;
        while (enet_host_service(host_.get(), &event, timeout) > 0) {
            switch (event.type) {
                case ENET_EVENT_TYPE_CONNECT: {
                    if (event.peer) {
                        spdlog::info("Client connected.");
                        client_ = peer {event.peer, peer_deleter {}};
                    }
                } break;
                case ENET_EVENT_TYPE_RECEIVE: {
                    if (event.packet) {
                        return packet<Tp>::from_ptr(reinterpret_cast<Tp *>(event.packet->data));
                    }
                } break;
                case ENET_EVENT_TYPE_DISCONNECT: {
                    spdlog::info("Client disconnected.");
                    client_ = nullptr;
                };
                default: break;
            }
        }

        return std::unexpected {"Failed to receive packet."};
    }
} // namespace enet


#endif // SERVER_H
