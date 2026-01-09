//
// Created by inquaterni on 12/31/25.
//

#ifndef PACKET_H
#define PACKET_H
#include <span>
#include <vector>

#include "../crypto/include/types.h"
#include "enet.h"
#include "packet.capnp.h"
#include "types.h"

namespace net {

    enum class packet_type: u8 {
        HANDSHAKE_CLIENT,
        HANDSHAKE_SERVER,
        RAW,
        COMPRESSED_ZSTD,
        ENCRYPTED_CHACHA20POLY1305,
    };

    template <packet_type type_t>
    struct packet {
        constexpr static packet_type type = type_t;
        std::vector<u8> body;

        constexpr packet() = default;

        explicit constexpr packet(const std::vector<u8> &data) noexcept : body(data) {}
        explicit constexpr packet(std::vector<u8> &&data) noexcept :
            body(std::forward<std::vector<u8>>(data)) {}
        explicit constexpr packet(const capnp::Data::Reader &reader) noexcept {
            body.assign(reader.begin(), reader.end());
        }
    };

    template <>
    struct packet<packet_type::HANDSHAKE_CLIENT> {
        constexpr static auto type = packet_type::HANDSHAKE_CLIENT;
        alignas(crypto_kx_PUBLICKEYBYTES) crypto::pkey_t public_key {};

        explicit constexpr packet(const crypto::pkey_t &public_key) noexcept : public_key(public_key) {}
        explicit constexpr packet(crypto::pkey_t &&public_key) noexcept : public_key(std::forward<crypto::pkey_t>(public_key)) {}
        explicit constexpr packet(const capnp::Data::Reader &reader) noexcept {
            std::ranges::copy(reader, public_key.begin());
        }
    };
    template <>
    struct packet<packet_type::HANDSHAKE_SERVER> {
        constexpr static auto type = packet_type::HANDSHAKE_SERVER;
        alignas(crypto_kx_PUBLICKEYBYTES) crypto::pkey_t public_key {};

        explicit constexpr packet(const crypto::pkey_t &public_key) noexcept : public_key(public_key) {}
        explicit constexpr packet(crypto::pkey_t &&public_key) noexcept : public_key(std::forward<crypto::pkey_t>(public_key)) {}
        explicit constexpr packet(const capnp::Data::Reader &reader) noexcept {
            std::ranges::copy(reader, public_key.begin());
        }
    };

    using client_hs_packet = packet<packet_type::HANDSHAKE_CLIENT>;
    using server_hs_packet = packet<packet_type::HANDSHAKE_SERVER>;

} // namespace enet



#endif //PACKET_H
