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
#ifndef EVENT_H
#define EVENT_H
#include <expected>
#include <string>
#include <variant>
#include "enet.h"
#include "event_bus.h"
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
        [[nodiscard]] constexpr std::span<u8> payload() { return std::span {packet->data, packet->dataLength}; }
    private:
        ENetPeer *_peer;
        u8 _channel_id;
        packet_ptr packet;
        constexpr receive_event(const u8 channel, ENetPeer *peer, packet_ptr &&packet) noexcept
            : _peer(peer), _channel_id(channel), packet(std::forward<packet_ptr>(packet)) {}
    };
    class pwd_request_event {
    public:
        constexpr pwd_request_event() noexcept = default;
    };
    class pwd_response_event {
    public:
        explicit constexpr pwd_response_event(std::string pwd) noexcept
        : password(std::move(pwd)) {}
        [[nodiscard]] constexpr const std::string& pwd() const { return password; }
    private:
        std::string password;
    };
    using event = std::variant<connect_event, disconnect_event, receive_event, pwd_request_event, pwd_response_event>;
    using event_bus_t = event_bus<event, RUSH_ALIGNED_CAPACITY(event, 16)>;
} // net
#endif //EVENT_H
