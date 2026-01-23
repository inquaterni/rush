//
// Created by inquaterni on 1/21/26.
//

#ifndef SESSION_H
#define SESSION_H
#include <memory>

#include "asio/posix/basic_stream_descriptor.hpp"
#include "asio/posix/stream_descriptor.hpp"
#include "asio/signal_set.hpp"
#include "client.h"
#include "signals.hpp"

namespace tunnel {
    static constexpr auto key_map = std::to_array<std::pair<net::u8, int>>({
        { 0x03, SIGINT },
        { 0x1C, SIGQUIT }
    });

    class session : public std::enable_shared_from_this<session> {
    public:
        constexpr session(asio::io_context &ctx, const std::shared_ptr<net::client> &c, crypto::cipher &cipher, asio::signal_set &sigset) noexcept
        : io_ctx(ctx),
          m_client(c),
          m_cipher(cipher),
          m_stream(ctx, dup(STDIN_FILENO)),
          m_signals(sigset) {}

        constexpr void do_read_stdin() noexcept;
        constexpr void do_wait_signal() noexcept;
        constexpr void start() noexcept;
        constexpr void stop() noexcept;
    private:
        asio::io_context &io_ctx;
        std::shared_ptr<net::client> m_client;
        crypto::cipher &m_cipher;
        asio::posix::stream_descriptor m_stream;
        asio::signal_set &m_signals;
        std::array<net::u8, 4096> m_buffer{};
    };
    constexpr void session::do_read_stdin() noexcept {
        auto self = shared_from_this();
        m_stream.async_read_some(asio::buffer(m_buffer, 4096), [self](const std::error_code ec, const std::size_t n) {
            if (ec)
                return;
            if (n <= 0)
                return;
            if (n == 1 && self->m_buffer[0] == 0x04) {
                spdlog::info("Ctrl+D. Closing.");
                self->stop();
                self->m_client->disconnect();
                return;
            }

            const auto data = std::vector<net::u8>{self->m_buffer.data(), self->m_buffer.data() + n};
            const auto pkt = net::shell_message{net::packet_type::BYTES, data};
            const auto words = serial::packet_serializer::serialize(pkt);
            const auto encrypted = self->m_cipher.encrypt(net::capnp_array_to_span(words));
            if (!encrypted) [[unlikely]] {
                self->do_read_stdin();
            }
            auto _ = self->m_client->send(*encrypted);
            self->do_read_stdin();
        });
    }
    constexpr void session::do_wait_signal() noexcept {
        auto self = shared_from_this();
        m_signals.async_wait([self](const std::error_code &ec, const int signo) {
            if (ec)
                return;

            switch (signo) {
                case SIGWINCH: {
                    winsize ws{};
                    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) [[unlikely]]
                        break;

                    const auto pkt = net::resize_packet{ws};
                    const auto words = serial::packet_serializer::serialize(pkt);
                    const auto encrypted = self->m_cipher.encrypt(net::capnp_array_to_span(words));
                    if (!encrypted) [[unlikely]] {
                        break;
                    }
                    auto _ = self->m_client->send(*encrypted, 1);
                } break;
                case SIGHUP:
                case SIGINT:
                case SIGQUIT:
                case SIGTERM:
                case SIGUSR1:
                case SIGUSR2: {
                    const auto msg = net::sig2name(signo);
                    if (!msg)
                        break;

                    const auto pkt = net::shell_message{net::packet_type::SIGNAL,
                                                        std::vector<net::u8>{msg->begin(), msg->end()}};
                    const auto words = serial::packet_serializer::serialize(pkt);
                    const auto encrypted = self->m_cipher.encrypt(net::capnp_array_to_span(words));
                    if (!encrypted) [[unlikely]] {
                        break;
                    }
                    auto _ = self->m_client->send(*encrypted);
                } break;
                default:
                    break;
            }
            self->do_wait_signal();
        });
    }
    constexpr void session::start() noexcept {
        do_read_stdin();
        do_wait_signal();
    }
    constexpr void session::stop() noexcept {
        std::error_code ec;
        m_stream.cancel(ec);
        m_signals.cancel(ec);
        m_stream.close(ec);
    }

} // tunnel

#endif //SESSION_H
