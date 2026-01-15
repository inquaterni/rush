//
// Created by inquaterni on 1/11/26.
//

#ifndef EVENT_H
#define EVENT_H
#include <expected>
#include <string>
#include <variant>


#include "enet.h"
#include "types.h"

namespace net {
    class connect_event {
    public:
        connect_event() = delete;

        [[nodiscard]]
        static constexpr std::expected<connect_event, std::string> create(ENetPeer *peer) noexcept {
            if (!peer) {
                return std::unexpected {"Event peer is NULL."};
            }
            return connect_event(peer);
        }

        [[nodiscard]] constexpr ENetPeer* peer() const { return _peer; }

    private:
        ENetPeer *_peer;
        explicit constexpr connect_event(ENetPeer *peer) noexcept : _peer(peer) {}
    };
    class disconnect_event {
    public:
        disconnect_event() = delete;

        [[nodiscard]]
        static constexpr std::expected<disconnect_event, std::string> create(ENetPeer *peer,
                                                                             const u32 data) noexcept {
            if (!peer) {
                return std::unexpected {"Event peer is NULL."};
            }
            return disconnect_event(peer, data);
        }

        [[nodiscard]] constexpr const ENetPeer* peer() const { return _peer; }
        constexpr void set_peer(ENetPeer *peer) { _peer = peer; }
        [[nodiscard]] constexpr u32 data() const { return _data; }

    private:
        ENetPeer *_peer;
        u32 _data;

        explicit constexpr disconnect_event(ENetPeer *peer, const u32 data = 0) noexcept
            : _peer(peer), _data(data) {}
    };
    class receive_event  {
    public:
        receive_event() = delete;

        [[nodiscard]]
        static constexpr std::expected<receive_event, std::string> create(const u8 channel, ENetPeer *peer, ENetPacket *packet) noexcept {
            if (!peer) {
                return std::unexpected {"Event peer is NULL."};
            }
            if (!packet) {
                return std::unexpected {"Event packet is NULL."};
            }
            auto raii_packet = packet_ptr {packet, packet_deleter {}};

            return receive_event(channel, peer, std::move(raii_packet));
        }

        [[nodiscard]] constexpr const ENetPeer *peer() const { return _peer; }
        [[nodiscard]] constexpr ENetPeer *peer() { return _peer; }
        [[nodiscard]] constexpr u8 channel_id() const { return _channel_id; }
        [[nodiscard]] constexpr std::span<const u8> payload() const { return std::span<const u8> {packet->data, packet->dataLength}; }

    private:
        ENetPeer *_peer;
        u8 _channel_id;
        packet_ptr packet;

        constexpr receive_event(const u8 channel, ENetPeer *peer, packet_ptr &&packet) noexcept
            : _peer(peer), _channel_id(channel), packet(std::forward<packet_ptr>(packet)) {}
    };
    using event = std::variant<connect_event, disconnect_event, receive_event>;
} // net

#endif //EVENT_H
