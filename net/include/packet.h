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
        XCHACHA20POLY1305,
    };

    struct generic_packet {
        packet_type type;
        std::vector<u8> body;

        explicit constexpr generic_packet(const packet_type type, const std::vector<u8> &data) noexcept :
            type(type), body(data) {}
        explicit constexpr generic_packet(const packet_type type, std::vector<u8> &&data) noexcept :
            type(type), body(std::forward<std::vector<u8>>(data)) {}
        explicit constexpr generic_packet(const packet_type type, const capnp::Data::Reader &reader) noexcept
        : type(type) {
            body.assign(reader.begin(), reader.end());
        }
    };

    struct handshake_packet {
        constexpr static auto type = packet_type::HANDSHAKE;
        alignas(crypto_kx_PUBLICKEYBYTES) crypto::pkey_t public_key {};

        explicit constexpr handshake_packet(const crypto::pkey_t &public_key) noexcept : public_key(public_key) {}
        explicit constexpr handshake_packet(crypto::pkey_t &&public_key) noexcept : public_key(std::forward<crypto::pkey_t>(public_key)) {}
        explicit constexpr handshake_packet(const capnp::Data::Reader &reader) noexcept {
            std::ranges::copy(reader, public_key.begin());
        }
    };

    using packet = std::variant<generic_packet, handshake_packet>;

    template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
    template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

} // namespace enet



#endif //PACKET_H
