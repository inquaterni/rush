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
#ifndef PTY_PUMPER_H
#define PTY_PUMPER_H
#include "asio/posix/stream_descriptor.hpp"
#include "cipher.h"
#include "host.h"
#include "packet.h"
#include "packet_serializer.h"
namespace net {
    class pty_pumper: public std::enable_shared_from_this<pty_pumper> {
    public:
        constexpr pty_pumper(asio::io_context &ctx, const int fd, host *host, ENetPeer *peer, crypto::cipher &c) noexcept :
            m_stream(ctx, dup(fd)), m_host(host), m_peer(peer), m_cipher(c) {}
        constexpr void start() noexcept {
            read_loop();
        }
        constexpr void stop() noexcept {
            std::error_code ec;
            m_stream.cancel(ec);
            m_stream.close(ec);
        }
        constexpr ~pty_pumper() noexcept {
            stop();
        }
    private:
        asio::posix::stream_descriptor m_stream;
        host *m_host;
        ENetPeer *m_peer;
        crypto::cipher &m_cipher;
        std::array<crypto::u8, 4096> m_buffer {};
        constexpr void read_loop() {
            m_stream.async_read_some(asio::buffer(m_buffer),
                [self = shared_from_this()](const std::error_code ec, const std::size_t n) {
                    if (ec) {
                        if (self->m_host && self->m_peer) {
                            self->m_host->disconnect(self->m_peer);
                        }
                        return;
                    }
                    if (self->m_host) {
                        const auto data = std::span (self->m_buffer.begin(), self->m_buffer.begin() + n);
                        const auto pkt = shell_message{packet_type::BYTES, data};
                        const auto words = serial::packet_serializer::serialize_into_pool(pkt);
                        auto encrypted = self->m_cipher.encrypt_inplace(*words);
                        if (!encrypted) return self->read_loop();
                        self->m_host->send(self->m_peer, std::move(*encrypted));
                    }
                    return self->read_loop();
                }
            );
        }
    };
} // net
#endif //PTY_PUMPER_H
