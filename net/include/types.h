//
// Created by inquaterni on 1/1/26.
//

#ifndef TYPES_H
#define TYPES_H
#include <memory>
#include <vector>
#include <span>
#include "../../cmake-build-debug/_deps/capnproto-src/c++/src/capnp/compiler/grammar.capnp.h"
#include "packet_deleter.h"

namespace net {
    using u8 = unsigned char;
    using u16 = unsigned short;
    using u32 = unsigned;
    using packet_ptr = std::unique_ptr<ENetPacket, packet_deleter>;

    constexpr std::span<const u8> capnp_array_to_span(const kj::Array<capnp::word> &words) {
        return std::span {reinterpret_cast<const u8 *>(words.begin()), words.size() * sizeof(capnp::word)};
    }
    constexpr std::vector<u8> capnp_array_to_vector(const kj::Array<capnp::word> &words) {
        const auto bytes = words.asBytes();
        return {bytes.begin(), bytes.end()};
    }

    constexpr std::span<const capnp::word> u8_vector_to_word_span(const std::vector<u8> &bytes) {
        return {reinterpret_cast<const capnp::word *>(bytes.data()), bytes.size() / sizeof(capnp::word)};
    }
    constexpr std::span<const capnp::word> u8_span_to_word_span(const std::span<const u8> bytes) {
        return {reinterpret_cast<const capnp::word *>(bytes.data()), bytes.size() / sizeof(capnp::word)};
    }
} // net

#endif //TYPES_H
