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
#include "schemas/packet.capnp.h"
#include "packet.h"

namespace serial {

class packet_serializer {
public:
    static constexpr kj::Array<capnp::word> serialize(const net::packet &pkt) {
        capnp::MallocMessageBuilder message;
        auto root = message.initRoot<Packet>();

        std::visit( net::overloaded {
            [&] (const net::handshake_packet &p) {
                auto hs = root.initHandshake();
                auto key_builder = hs.initPublicKey(p.public_key.size());
                std::ranges::copy(p.public_key, key_builder.begin());
            },
            [&] (const net::generic_packet &p) {
                switch (p.type) {
                    case net::packet_type::XCHACHA20POLY1305: {
                        auto data = root.initXchacha20Poly1305(p.body.size());
                        std::ranges::copy(p.body, data.begin());
                    } break;
                    default: assert(0 && "Unreachable");
                }
            }
        }, pkt);

        return capnp::messageToFlatArray(message);
    }

    static constexpr std::expected<net::packet, std::string> deserialize(const std::span<const capnp::word> &data) {
        try {
            capnp::FlatArrayMessageReader reader{kj::arrayPtr(data.data(), data.size())};

            switch (const auto packet_reader = reader.getRoot<Packet>(); packet_reader.which()) {
                case Packet::HANDSHAKE: {
                    const auto key = packet_reader.getHandshake();
                    return net::handshake_packet {key.getPublicKey()};
                }
                case Packet::XCHACHA20_POLY1305: {
                    const auto encrypted = packet_reader.getXchacha20Poly1305();
                    return net::generic_packet {net::packet_type::XCHACHA20POLY1305, encrypted};
                }
                default: assert(0 && "Unreachable");
            }
        } catch (const kj::Exception &e) {
            return std::unexpected {"While deserializing data exception was thrown: " + std::string {e.getDescription().cStr()}};
        }
    }
};

} // serial

#endif //PACKET_SERIALIZER_H
