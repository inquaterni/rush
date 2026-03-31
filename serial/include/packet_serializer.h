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
#include "object_pool.h"
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
                    case net::packet_type::BYTES: {
                        auto data = root.initBytes(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::DISCONNECT: {
                        auto data = root.initDisconnect(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::SIGNAL: {
                        auto data = root.initSignal(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::AUTH_RESPONSE: {
                        auto data = root.initAuthResponse(p.bytes.size());
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
            },
            [&] (const net::auth_packet &p) {
                auto auth = root.initAuthRequest();
                auth.setUsername(p.username);
                auth.setPasswd(p.password);
            }
        }, pkt);

        return capnp::messageToFlatArray(message);
    }

    static auto serialize_into_pool(const net::packet &pkt) {
        size_t max_size = 256;
        std::visit(net::overloaded{
            [&](const net::handshake_packet &p) { max_size += p.public_key.size(); },
            [&](const net::shell_message &p) { max_size += p.bytes.size(); },
            [&](const net::resize_packet &) { },
            [&](const net::auth_packet &p) { max_size += p.username.size() + p.password.size(); }
        }, pkt);

        max_size = (max_size + sizeof(capnp::word) - 1) & ~(sizeof(capnp::word) - 1);

        auto buf = net::object_pool<std::vector<net::u8>>::get_instance().acquire();
        buf->assign(max_size, 0);

        auto* out_words = reinterpret_cast<capnp::word*>(buf->data());
        const auto word_span = kj::arrayPtr(
            out_words + 1,
            buf->size() / sizeof(capnp::word) - 1
        );

        capnp::FlatMessageBuilder message(word_span);
        auto root = message.initRoot<Packet>();

        std::visit( net::overloaded {
            [&] (const net::handshake_packet &p) {
                auto hs = root.initHandshake();
                auto key_builder = hs.initPublicKey(p.public_key.size());
                std::ranges::copy(p.public_key, key_builder.begin());
            },
            [&] (const net::shell_message &p) {
                switch (p.type) {
                    case net::packet_type::BYTES: {
                        auto data = root.initBytes(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::DISCONNECT: {
                        auto data = root.initDisconnect(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::SIGNAL: {
                        auto data = root.initSignal(p.bytes.size());
                        std::ranges::copy(p.bytes, data.begin());
                    } break;
                    case net::packet_type::AUTH_RESPONSE: {
                        auto data = root.initAuthResponse(p.bytes.size());
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
            },
            [&] (const net::auth_packet &p) {
                auto auth = root.initAuthRequest();
                auth.setUsername(p.username);
                auth.setPasswd(p.password);
            }
        }, pkt);

        auto segments = message.getSegmentsForOutput();
        assert(segments.size() == 1 && "Message grew beyond 1 segment!");

        // Write the segment table.
        // Word 0 contains:
        // bytes 0..3: number of segments - 1 (which is 0)
        // bytes 4..7: size of segment 0 in words
        auto* table = reinterpret_cast<net::u8*>(out_words);
        table[0] = 0; table[1] = 0; table[2] = 0; table[3] = 0;
        const net::u32 size = segments[0].size();
        table[4] = size & 0xFF; table[5] = size >> 8 & 0xFF;
        table[6] = size >> 16 & 0xFF; table[7] = size >> 24 & 0xFF;

        buf->resize((1 + size) * sizeof(capnp::word));
        return buf;
    }

    static constexpr std::expected<net::packet, std::string> deserialize(const std::span<const capnp::word> &data) {
        if (data.empty()) {
            return std::unexpected{"Packet is empty."};
        }

        const auto* table = reinterpret_cast<const uint32_t*>(data.data());
        const uint32_t segments_count = table[0] + 1;
        if (segments_count > 64) {
            return std::unexpected{"Packet specifies too many segments."};
        }
        const size_t table_words = segments_count / 2 + 1;
        if (data.size() < table_words) {
            return std::unexpected{"Packet smaller than segment table."};
        }
        size_t total_words = table_words;
        for (uint32_t i = 0; i < segments_count; ++i) {
            const uint32_t segment_sz = table[i + 1];
            if (total_words + segment_sz < total_words) {
                return std::unexpected{"Segment size overflow."};
            }
            total_words += segment_sz;
        }
        if (data.size() < total_words) {
            return std::unexpected{"Packet data smaller than advertised segment sizes."};
        }
#if RUSH_EXCEPTIONS_ENABLED
        try {
#endif
            capnp::FlatArrayMessageReader reader{kj::arrayPtr(data.data(), data.size())};

            switch (const auto packet_reader = reader.getRoot<Packet>(); packet_reader.which()) {
                case Packet::HANDSHAKE: {
                    const auto key = packet_reader.getHandshake();
                    return net::handshake_packet {key.getPublicKey()};
                }
                case Packet::BYTES: {
                    const auto bytes = packet_reader.getBytes();
                    return net::shell_message {net::packet_type::BYTES, bytes};
                }
                case Packet::DISCONNECT: {
                    const auto disconnect = packet_reader.getDisconnect();
                    return net::shell_message {net::packet_type::DISCONNECT, disconnect};
                }
                case Packet::SIGNAL: {
                    const auto bytes = packet_reader.getSignal();
                    return net::shell_message {net::packet_type::SIGNAL, bytes};
                }
                case Packet::AUTH_REQUEST: {
                    const auto auth = packet_reader.getAuthRequest();
                    return net::auth_packet {auth.getUsername(), auth.getPasswd()};
                }
                case Packet::AUTH_RESPONSE: {
                    const auto auth = packet_reader.getAuthResponse();
                    return net::shell_message {net::packet_type::AUTH_RESPONSE, auth};
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
#if RUSH_EXCEPTIONS_ENABLED
        } catch (const kj::Exception &e) {
            return std::unexpected {"While deserializing data exception was thrown: " + std::string {e.getDescription().cStr()}};
        }
#endif
        assert(0 && "Unreachable");
        return std::unexpected {"Unreachable"};
    }
};

} // serial

#endif //PACKET_SERIALIZER_H
