//
// Created by inquaterni on 12/31/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include <expected>
#include <memory>
#include <thread>
#include <utility>

#include "../net/include/host_deleter.h"
#include "../net/include/peer_deleter.h"
#include "concurrentqueue.h"
#include "packet.h"
#include "packet_serializer.h"

namespace net {
    class client {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        using peer = std::unique_ptr<ENetPeer, peer_deleter>;
        client() = delete;

        [[nodiscard]]
        static std::expected<client, std::string> create() noexcept;

        bool connect(std::string_view /* address */, int /* port */, short timeout = 5000) noexcept;
        [[nodiscard]]
        constexpr bool send(const packet &pkt, u8 channel_id = 0,
                  u32 flags = ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE) const noexcept;
        constexpr void service(int timeout = 1000);
        constexpr std::expected<packet, std::string> recv();

    private:
        host host_;
        peer server;
        moodycamel::ConcurrentQueue<ENetEvent> events {};
        std::jthread service_;

        explicit client(host && /* client host */) noexcept;
    };
    constexpr std::expected<packet, std::string> client::recv() {
        ENetEvent event;
        if (!events.try_dequeue(event)) {
            return std::unexpected { "No events found." };
        }

        switch (event.type) {
            case ENET_EVENT_TYPE_RECEIVE: {
                if (!event.packet) return std::unexpected("No data received.");
                const auto word_ptr = reinterpret_cast<const capnp::word *>(event.packet->data);
                const std::size_t word_size = event.packet->dataLength / sizeof(capnp::word);
                return serial::packet_serializer::deserialize(std::span {word_ptr, word_size});
            }
            default: return std::unexpected("Unexpected event type.");
        }
    }

    constexpr bool client::send(const packet &pkt, const u8 channel_id, const u32 flags) const noexcept {
        if (!server) {
            return false;
        }

        const auto words = serial::packet_serializer::serialize(pkt);
        const auto p = enet_packet_create(words.asBytes().begin(), words.size() * sizeof(capnp::word), flags);
        if (!p) {
            return false;
        }
        enet_peer_send(server.get(), channel_id, p);
        enet_host_flush(host_.get());

        return true;
    }
    constexpr void client::service(const int timeout) {
        service_ = std::jthread {[&] (const std::stop_token &stop_token) {
            ENetEvent event;
            while (!stop_token.stop_requested()) {
                if (enet_host_service(host_.get(), &event, timeout) <= 0) continue;

                switch (event.type) {
                    case ENET_EVENT_TYPE_CONNECT: {
                        server = peer {event.peer, peer_deleter{}};
                    } break;
                    case ENET_EVENT_TYPE_DISCONNECT:
                    case ENET_EVENT_TYPE_RECEIVE:
                    case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
                        events.enqueue(event);
                    } break;
                    default: break;
                }
            }
        }};

        service_.detach();
    }
} // net



#endif //CLIENT_H
