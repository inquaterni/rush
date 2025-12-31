//
// Created by inquaterni on 12/31/25.
//

#ifndef PACKET_H
#define PACKET_H
#include <array>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <sodium/crypto_kx.h>
#include "enet.h"
#include "packet_deleter.h"

namespace enet {
    using u8 = unsigned char;
    using u32 = unsigned;

    using pkey_t = std::array<u8, crypto_kx_PUBLICKEYBYTES>;

    enum class packet_type: u8 {
        HANDSHAKE_CLIENT,
        HANDSHAKE_SERVER,
    };


    struct client_hs_payload {
        static constexpr auto type = packet_type::HANDSHAKE_CLIENT;
        alignas(crypto_kx_PUBLICKEYBYTES) pkey_t public_key;

        client_hs_payload() = default;

        explicit client_hs_payload(const pkey_t &public_key) : public_key(public_key) {}
        explicit client_hs_payload(pkey_t &&public_key) : public_key(std::forward<pkey_t>(public_key)) {}
    };

    struct server_hs_payload {
        static constexpr auto type = packet_type::HANDSHAKE_SERVER;
        alignas(crypto_kx_PUBLICKEYBYTES) pkey_t public_key;

        server_hs_payload() = default;

        explicit server_hs_payload(const pkey_t &public_key) : public_key(public_key) {}
        explicit server_hs_payload(pkey_t &&public_key) : public_key(std::forward<pkey_t>(public_key)) {}
    };

    template<typename TPayload>
    class packet {
    public:
        packet() = default;
        explicit packet(const TPayload &) noexcept;
        explicit packet(TPayload &&) noexcept;

        constexpr static std::expected<packet, std::string> from_ptr(TPayload *) noexcept;
        [[nodiscard]]
        constexpr TPayload &get_payload();

        [[nodiscard]]
        std::unique_ptr<ENetPacket, packet_deleter> to_enet(u32 flags = ENET_PACKET_FLAG_RELIABLE) const;

    private:
        TPayload payload;
    };
    template<typename TPayload>
    constexpr std::expected<packet<TPayload>, std::string> packet<TPayload>::from_ptr(TPayload *ptr) noexcept {
        if (!ptr) {
            return std::unexpected{"Pointer was null."};
        }
        TPayload payload {};
        std::memcpy(&payload, ptr, sizeof(TPayload));

        return packet{std::move(payload)};
    }
    template<typename TPayload>
    constexpr TPayload &packet<TPayload>::get_payload() {
        return payload;
    }
    template<typename TPayload>
    packet<TPayload>::packet(const TPayload &payload) noexcept : payload(payload) {}
    template<typename TPayload>
    packet<TPayload>::packet(TPayload &&payload) noexcept : payload(std::forward<TPayload>(payload)) {}
    template<typename TPayload>
    std::unique_ptr<ENetPacket, packet_deleter> packet<TPayload>::to_enet(const u32 flags) const {
        std::array<u8, sizeof(TPayload)> buffer;
        buffer[0] = static_cast<u8>(TPayload::type);
        std::memcpy(&buffer[1], &payload, sizeof(TPayload));

        return std::unique_ptr<ENetPacket, packet_deleter>(enet_packet_create(buffer.data(), buffer.size(), flags), packet_deleter {});
    }
} // namespace enet



#endif //PACKET_H
