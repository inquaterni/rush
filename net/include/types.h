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
#ifndef TYPES_H
#define TYPES_H
#include <memory>
#include <vector>
#include <span>
#include <capnp/common.h>
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
