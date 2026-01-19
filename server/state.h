//
// Created by inquaterni on 1/14/26.
//

#ifndef STATE_H
#define STATE_H
#include <memory>
#include <spdlog/spdlog.h>
#include <utility>
#include <variant>

#include "../pack/include/compressor.h"
#include "cipher.h"
#include "host.h"
#include "keys_factory.h"
#include "packet_serializer.h"
#include "session.h"
#include "signals.hpp"
#include "state.h"
#include "xchacha20poly1305.h"

namespace net {
    using namespace std::chrono_literals;

    struct disconnect_t {
        std::string reason {};
    };
    struct keep_state_t {};
    class state;
    class handshake;
    class conn_confirm;
    class connected;

    static constexpr u8 c_confirm_magic[] = "CONFIRM";
    static constexpr u8 s_confirm_magic[] = "OK";

    // NOTE: `side` is one WHO CHECKS!!!!! That means: if SERVER side checks, this function checks for CLIENT magic
    template<crypto::side side>
    static constexpr bool is_confirm(const std::vector<u8> &data) {
        if constexpr (side == crypto::side::CLIENT) {
            return data.size() == sizeof(s_confirm_magic) &&
                   std::memcmp(data.data(), s_confirm_magic, sizeof(s_confirm_magic)) == 0;
        } else {
            return data.size() == sizeof(c_confirm_magic) &&
                   std::memcmp(data.data(), c_confirm_magic, sizeof(c_confirm_magic)) == 0;
        }
    }

    class state {
    public:
        constexpr state() noexcept = default;
        virtual ~state() = default;

        state& operator=(state&&) = default;
        state(state&&) = default;

        state& operator=(const state&) = delete;
        state(const state&) = delete;

        constexpr auto dispatch(this auto&& self, auto&&... args) noexcept {
            static_assert(requires { self.handle(std::forward<decltype(args)>(args)...); },
                "Derived class must implement `handle` member.");
            return self.handle(std::forward<decltype(args)>(args)...);
        }
    };
    class handshake final : public state {
    public:
        inline static constinit auto max_handshake_duration = 500ms;
        inline static constinit auto max_retries = 3;

        handshake(handshake&&) = default;
        handshake& operator=(handshake &&other) noexcept {
            if (this != &other) {
                this->pair = other.pair;
                this->hs_start_point = other.hs_start_point;
                this->retries = other.retries;
            }
            return *this;
        }

        constexpr explicit handshake(crypto::key_pair &pair) noexcept
        : pair(pair) {}

        auto handle(const std::shared_ptr<host> &h, receive_event &e, const pty::session &) noexcept;

    private:
        crypto::key_pair &pair;
        std::chrono::steady_clock::time_point hs_start_point{std::chrono::steady_clock::now()};
        int retries{0};
    };
    class conn_confirm final : public state {
    public:
        inline static constinit auto max_confirmation_duration = 250ms;

        conn_confirm(conn_confirm&&) = default;
        conn_confirm& operator=(conn_confirm&&) = default;

        constexpr explicit conn_confirm(crypto::cipher &&c) noexcept
        : cipher_(std::forward<crypto::cipher>(c)) {}

        constexpr explicit conn_confirm(std::unique_ptr<crypto::encryption> &&encryptor) noexcept
        : cipher_(std::forward<std::unique_ptr<crypto::encryption>>(encryptor)) {}

        auto handle(const std::shared_ptr<host> &h, receive_event &e, const pty::session &) noexcept;
    private:
        std::chrono::steady_clock::time_point confirm_start_point {std::chrono::steady_clock::now()};
        crypto::cipher cipher_;
    };

    struct connection_data {
        crypto::cipher cipher;
        std::shared_ptr<host> host_;
        ENetPeer* peer;

        connection_data(crypto::cipher&& c, std::shared_ptr<host> h, ENetPeer* p)
            : cipher(std::move(c)), host_(std::move(h)), peer(p) {}
    };
    class connected final : public state {
    public:
        constexpr explicit connected(crypto::cipher &&c, const std::shared_ptr<host>& h, ENetPeer *peer, const pty::session &session) noexcept
        : data_(std::make_unique<connection_data>(std::forward<crypto::cipher>(c), h, peer)) {
            pump = std::jthread([data = data_.get(), &session] (const std::stop_token &st) {
                pump_pty_to_network(st, session, data);
            });
        }

        connected(connected&&) = default;
        connected& operator=(connected&&) = default;

        static constexpr void pump_pty_to_network(const std::stop_token &st, const pty::session &session,
                                                  const connection_data *data) noexcept;

        [[nodiscard]]
        auto handle(const std::shared_ptr<host> &h, const receive_event &e, const pty::session &session) const noexcept;
    private:
        std::unique_ptr<connection_data> data_;
        std::jthread pump;
    };

    using state_t = std::variant<handshake, conn_confirm, connected>;
    using transition_t = std::variant<keep_state_t, disconnect_t, state_t>;

    struct transition {
        static constexpr transition_t keep() noexcept { return {keep_state_t {}}; }
        static constexpr transition_t disconnect() noexcept { return {disconnect_t{}}; }
        static constexpr transition_t disconnect(std::string reason) noexcept {
            return {disconnect_t{std::move(reason)}};
        }
        template <class T>
        requires std::derived_from<std::remove_cvref_t<T>, state> &&
            std::constructible_from<state_t, std::remove_cvref_t<T>>
        static constexpr transition_t to(T&& new_state) noexcept {
            return state_t(std::forward<T>(new_state));
        }
    };

    class peer_context {
    public:
        using host_ptr = std::shared_ptr<host>;

        peer_context(host_ptr host, state_t &&state, pty::session &&s) noexcept
        : m_host(std::move(host)),
        state(std::forward<state_t>(state)),
        pty(std::forward<pty::session>(s)) {}
        constexpr void handle(receive_event &e) noexcept;

    private:
        host_ptr m_host;
        state_t state;
        pty::session pty;
    };


    inline auto handshake::handle(const std::shared_ptr<host> &h, receive_event &e, const pty::session &) noexcept {
        if (std::chrono::steady_clock::now() - hs_start_point > max_handshake_duration) {
            return transition::disconnect("Timeout reached.");
        }
        const auto pkt = serial::packet_serializer::deserialize(u8_span_to_word_span(e.payload()));
        if (!pkt) [[unlikely]] {
            if (retries++ > max_retries) {
                return transition::disconnect("Maximum retries exceeded.");
            }
            return transition::keep();
        }
        const auto *const hs = std::get_if<handshake_packet>(&*pkt);
        if (!hs) [[unlikely]] {
            if (retries++ > max_retries) {
                return transition::disconnect("Maximum retries exceeded.");
            }
            return transition::keep();
        }
        const auto sk = crypto::keys_factory::enroll<crypto::side::SERVER>(pair, hs->public_key);
        if (!sk) [[unlikely]] {
            if (retries++ > max_retries) {
                return transition::disconnect("Maximum retries exceeded.");
            }
            return transition::keep();
        }
        if (!h->send(e.peer(), handshake_packet{pair.cpublic_key()})) [[unlikely]] {
            if (retries++ > max_retries) {
                return transition::disconnect("Maximum retries exceeded.");
            }

            return transition::keep();
        }

        auto encryptor = std::make_unique<crypto::xchacha20poly1305>(*sk);
        return transition::to(conn_confirm{std::move(encryptor)});
    }
    inline auto conn_confirm::handle(const std::shared_ptr<host> &h, receive_event &e, const pty::session &pty) noexcept {
        if (std::chrono::steady_clock::now() - confirm_start_point > max_confirmation_duration) {
            return transition::disconnect("Timeout reached.");
        }
        const auto decrypted = cipher_.decrypt(e.payload());
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        const auto pkt = serial::packet_serializer::deserialize(u8_vector_to_word_span(*decrypted));
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }
        const auto *const sh_msg = std::get_if<shell_message>(&*pkt);
        if (!sh_msg || sh_msg->type != packet_type::STDIN) [[unlikely]] {
            return transition::keep();
        }
        if (!is_confirm<crypto::side::SERVER>(sh_msg->bytes)) {
            return transition::keep();
        }
        const auto s_pkt = shell_message{packet_type::STDIN, std::vector(s_confirm_magic, s_confirm_magic + sizeof(s_confirm_magic))};
        const auto words = serial::packet_serializer::serialize(s_pkt);
        const auto encrypted = cipher_.encrypt(capnp_array_to_span(words));
        if (!encrypted) [[unlikely]] {
            return transition::keep();
        }
        if (!h->send(e.peer(), *encrypted)) {
            return transition::keep();
        }

        return transition::to(connected{std::move(cipher_), h, e.peer(), pty});
    }
    inline auto connected::handle(const std::shared_ptr<host> & /* h */, const receive_event &e,
                                  const pty::session &session) const noexcept {
        const auto decrypted = data_->cipher.decrypt(e.payload());
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        const auto pkt = serial::packet_serializer::deserialize(u8_vector_to_word_span(*decrypted));
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }

        return std::visit(overloaded {
            [&] (const shell_message &sh_msg) {
                switch (sh_msg.type) {
                    case packet_type::STDIN: {
                        if (!sh_msg.bytes.empty()) {
                            if (!session.write(sh_msg.bytes)) {
                                spdlog::error("Failed to write.");
                                return transition::keep();
                            }
                        }
                    } break;
                    case packet_type::SIGNAL: {
                        const auto str = std::string_view {reinterpret_cast<const char *>(sh_msg.bytes.data()), sh_msg.bytes.size()};
                        ioctl(session.fd(), TIOCSIG, name2sig(str));
                    } break;
                    default: return transition::keep();
                }

                return transition::keep();

            },
            [&] (const resize_packet &win_resize) {
                ioctl(session.fd(), TIOCSWINSZ, &win_resize.ws);
                return transition::keep();
            },
            [&] (auto &&) {return transition::keep();}
        }, *pkt);
    }
    constexpr void connected::pump_pty_to_network(const std::stop_token &st,
                                                  const pty::session &session,
                                                  const connection_data *data) noexcept {
        std::array<char, 4096> buffer {};
        pollfd pfd {};
        pfd.fd = session.fd();
        pfd.events = POLLIN;

        while (!st.stop_requested()) {
            const int ret = poll(&pfd, 1, 16);
            if (ret < 0) break;
            if (ret == 0) continue;

            if (pfd.revents & POLLIN) {
                const long unsigned int n = read(session.fd(), buffer.data(), buffer.size());
                if (n <= 0) break;
                if (n > buffer.max_size()) continue;
                const auto pkt = shell_message{packet_type::STDIN, std::vector<u8>(buffer.begin(), buffer.begin() + n)};
                const auto words = serial::packet_serializer::serialize(pkt);
                const auto encrypted = data->cipher.encrypt(capnp_array_to_span(words));
                if (!encrypted) [[unlikely]] continue;
                if (!data->host_) break;
                if (!data->peer) break;
                data->host_->send(data->peer, *encrypted);
            }
        }
    }
    constexpr void peer_context::handle(receive_event &e) noexcept {
        auto transition = std::visit<transition_t>(overloaded {
            [&] (auto &s) constexpr {
                return s.handle(m_host, e, this->pty);
            }
        }, state);

        std::visit<void>(overloaded {
            [] (keep_state_t) constexpr {},
                [&] (const disconnect_t &) constexpr {
                    if (!this->m_host) [[unlikely]] {
                        return;
                    }
                    // TODO: Send disconnect reason back to client
                    // this->m_host->send();
                    this->m_host->disconnect(e.peer());
                },
            [&] (state_t &&new_state) constexpr {
                this->state = std::forward<state_t>(new_state);
            }
        }, std::move(transition));
    }
} // net



#endif //STATE_H
