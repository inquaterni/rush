//
// Created by inquaterni on 12/31/25.
//

#ifndef PACKET_H
#define PACKET_H
#include <variant>
#include <vector>
#include "../crypto/include/types.h"

#include "capnp/blob.h"
#include "types.h"

namespace net {
    enum class packet_type: u8 {
        HANDSHAKE,
        BYTES,
        DISCONNECT,
        SIGNAL,
        AUTH_REQUEST,
        AUTH_RESPONSE,
        RESIZE
    };

    struct shell_message {
        packet_type type;
        std::span<const u8> bytes;

        constexpr shell_message(const packet_type type, const std::span<const u8> data) noexcept :
            type(type), bytes(data) {}
        constexpr shell_message(const packet_type type, std::vector<u8> &data) noexcept :
            type(type), bytes(data) {}
        template <std::size_t N>
        constexpr shell_message(const packet_type type, std::array<u8, N> &data) noexcept :
            type(type), bytes(data) {}
        template <std::size_t N>
        constexpr shell_message(const packet_type type, std::array<u8, N> &data, std::size_t n) noexcept :
            type(type), bytes(data.data(), n) {}
        constexpr shell_message(const packet_type type, const capnp::Data::Reader &reader) noexcept
        : type(type), bytes(reader.asBytes()) {}
        constexpr shell_message(const packet_type type, const std::string_view view) noexcept :
            type(type), bytes(reinterpret_cast<const u8*>(view.data()), view.size()) {}
    };
    struct handshake_packet {
        constexpr static auto type = packet_type::HANDSHAKE;
        alignas(crypto_kx_PUBLICKEYBYTES) crypto::pkey_t public_key {};

        explicit constexpr handshake_packet(const crypto::pkey_t &public_key) noexcept : public_key(public_key) {}
        explicit constexpr handshake_packet(const capnp::Data::Reader &reader) noexcept {
            std::ranges::copy(reader, public_key.begin());
        }
    };
    struct resize_packet {
        constexpr static auto type = packet_type::RESIZE;
        winsize ws {};

        explicit constexpr resize_packet(const winsize ws) noexcept : ws(ws) {}
        explicit constexpr resize_packet(winsize &&ws) noexcept : ws(std::forward<winsize>(ws)) {}
    };
    struct auth_packet {
        constexpr static auto type = packet_type::AUTH_REQUEST;
        std::string_view username {};
        std::string_view password {};

        constexpr auth_packet(const std::string_view username, const std::string_view password) noexcept
        : username(username), password(password) {}

        constexpr auth_packet(const capnp::Text::Reader &username_reader, const capnp::Text::Reader &password_reader) noexcept
        : username(username_reader.cStr(), username_reader.size()), password(password_reader.cStr(), password_reader.size()) {}
    };

    using packet = std::variant<shell_message, handshake_packet, resize_packet, auth_packet>;

    template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
    template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

} // namespace enet



#endif //PACKET_H
