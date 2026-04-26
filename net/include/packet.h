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
