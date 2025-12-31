//
// Created by inquaterni on 12/31/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include <expected>
#include <memory>

#include "../core/include/host_deleter.h"
#include "../core/include/peer_deleter.h"
#include "packet.h"

namespace enet {
    class client {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        using peer = std::unique_ptr<ENetPeer, peer_deleter>;
        client() = delete;

        [[nodiscard]]
        static std::expected<client, std::string> create() noexcept;

        bool connect(std::string_view /* address */, int /* port */, short timeout = 5000) noexcept;

        template<typename Tp>
        bool send(const packet<Tp> & /* packet */, u8 channel_id = 0) noexcept;

        template<typename Tp>
        std::expected<packet<Tp>, std::string> recv(int timeout = 1000);

    private:
        host host_;
        peer server;

        explicit client(host && /* client host */) noexcept;
    };
    template<typename Tp>
    bool client::send(const packet<Tp> &pack, const u8 channel_id) noexcept {
        const auto enet_pack = pack.to_enet();
        if (!enet_pack) {
            return false;
        }

        enet_peer_send(server.get(), channel_id, enet_pack.get());
        enet_host_flush(host_.get());
        return true;
    }
    template<typename Tp>
    std::expected<packet<Tp>, std::string> client::recv(const int timeout) {
        ENetEvent event;
        while (enet_host_service(host_.get(), &event, timeout) > 0) {
            switch (event.type) {
                case ENET_EVENT_TYPE_RECEIVE: {
                    if (event.packet) {
                        return packet<Tp>::from_ptr(reinterpret_cast<Tp *>(event.packet->data));
                    }
                } break;

                default:
                    break;
            }
        }
        return std::unexpected {"Failed to receive packet."};
    }
} // namespace enet



#endif //CLIENT_H
