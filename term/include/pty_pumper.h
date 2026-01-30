//
// Created by inquaterni on 1/20/26.
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
                    if (ec) return;

                    if (self->m_host) {
                        const auto data = std::vector (self->m_buffer.begin(), self->m_buffer.begin() + n);
                        const auto pkt = shell_message{packet_type::BYTES, data};
                        const auto words = serial::packet_serializer::serialize(pkt);
                        const auto encrypted = self->m_cipher.encrypt(capnp_array_to_span(words));
                        if (!encrypted) self->read_loop();
                        self->m_host->send(self->m_peer, *encrypted);
                    }

                    self->read_loop();
                }
            );
        }
    };

} // net

#endif //PTY_PUMPER_H
