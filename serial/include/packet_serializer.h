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
            [&] (const net::shell_message &p) {
                switch (p.type) {
                    case net::packet_type::STDIN: {
                        auto data = root.initStdin(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::SIGNAL: {
                        auto data = root.initSignal(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    default: assert(0 && "Unreachable");
                }
            },
            [&] (const net::resize_packet &p) {
                auto ws = root.initResize();
                ws.setWsRow(p.ws.ws_row);
                ws.setWsCol(p.ws.ws_col);
                ws.setWsXpixel(p.ws.ws_xpixel);
                ws.setWsYpixel(p.ws.ws_ypixel);
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
                case Packet::STDIN: {
                    const auto bytes = packet_reader.getStdin();
                    return net::shell_message {net::packet_type::STDIN, bytes};
                }
                case Packet::SIGNAL: {
                    const auto bytes = packet_reader.getSignal();
                    return net::shell_message {net::packet_type::SIGNAL, bytes};
                }
                case Packet::RESIZE: {
                    const auto ws_reader = packet_reader.getResize();
                    const auto ws = winsize {
                        .ws_row = ws_reader.getWsRow(),
                        .ws_col = ws_reader.getWsCol(),
                        .ws_xpixel = ws_reader.getWsXpixel(),
                        .ws_ypixel = ws_reader.getWsYpixel()
                    };
                    return net::resize_packet {ws};
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
