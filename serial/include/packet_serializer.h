//
// Created by inquaterni on 1/7/26.
//

#ifndef PACKET_SERIALIZER_H
#define PACKET_SERIALIZER_H
#include <capnp/message.h>
#include <capnp/serialize.h>
#include <expected>
#include <kj/array.h>
#include <span>
#include <string>

#include "packet.capnp.h"

namespace serial {

class packet_serializer {
    using u8 = unsigned char;
    static constexpr u8 HANDSHAKE_CLIENT = 0;
    static constexpr u8 HANDSHAKE_SERVER = 1;
public:
    template<typename Tp>
    static constexpr std::expected<kj::Array<capnp::word>, std::string> serialize(const Tp &packet) {
        ::capnp::MallocMessageBuilder message;

        Packet::Builder builder = message.initRoot<Packet>();
        builder.setType(static_cast<::PacketType>(Tp::type));

        try {
            if constexpr (static_cast<u8>(Tp::type) == HANDSHAKE_CLIENT) {
                auto body = builder.getBody().initHandshakeClient();
                body.setPublicKey(capnp::Data::Reader(packet.public_key.data(), packet.public_key.size()));
            } else if constexpr (static_cast<u8>(Tp::type) == HANDSHAKE_SERVER) {
                auto body = builder.getBody().initHandshakeServer();
                body.setPublicKey(capnp::Data::Reader(packet.public_key.data(), packet.public_key.size()));
            } else {
                builder.getBody().setGeneric(capnp::Data::Reader(packet.body.data(), packet.body.size()));
            }

            return capnp::messageToFlatArray(message);
        } catch (const kj::Exception &e) {
            return std::unexpected { "Exception thrown: " + std::string { e.getDescription().cStr() } };
        }
    }

    template<typename Tp>
    static constexpr std::expected<Tp, std::string> deserialize(const std::span<const capnp::word> &data) {
        capnp::FlatArrayMessageReader reader{kj::arrayPtr(data.data(), data.size())};
        const auto packet_reader = reader.getRoot<Packet>();

        if (static_cast<u8>(packet_reader.getType()) != static_cast<u8>(Tp::type)) {
            return std::unexpected {"Packet types mismatch, got: " + std::to_string(static_cast<u8>(packet_reader.getType())) + ", expected: " + std::to_string(static_cast<u8>(Tp::type)) + "."};
        }
        try {
            if constexpr (static_cast<u8>(Tp::type) == HANDSHAKE_CLIENT) {
                const auto hs = packet_reader.getBody().getHandshakeClient();
                return Tp {std::move(hs.getPublicKey())};
            } else if constexpr (static_cast<u8>(Tp::type) == HANDSHAKE_SERVER) {
                const auto hs = packet_reader.getBody().getHandshakeServer();
                return Tp {std::move(hs.getPublicKey())};
            }

            return Tp {std::move(packet_reader.getBody().getGeneric())};
        } catch (const kj::Exception &e) {
            return std::unexpected { "Exception thrown: " + std::string { e.getDescription().cStr() } };
        }
    }
};

} // serial

#endif //PACKET_SERIALIZER_H
