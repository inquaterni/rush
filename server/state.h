//
// Created by inquaterni on 1/14/26.
//

#ifndef STATE_H
#define STATE_H
#include <memory>
#include <spdlog/spdlog.h>
#include <utility>
#include <variant>

#include "../client/state.h"
#include "cipher.h"
#include "host.h"
#include "keys_factory.h"
#include "packet_serializer.h"
#include "pty_pumper.h"
#include "session.h"
#include "signals.hpp"
#include "state.h"
#include "xchacha20poly1305.h"

namespace net {
    using namespace std::chrono_literals;

    struct keep_state_t {};
    struct disconnect_t {
        std::string reason {};
    };
    struct establish_t {
        crypto::cipher cipher;
    };
    struct activate_session_t {
        std::string username;
        std::string password;
    };
    class state;
    class handshake;
    class conn_confirm;
    class auth;
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
        inline static constinit auto max_duration = 500ms;
        inline static constinit auto max_retries = 3;

        constexpr handshake() noexcept = default;

        handshake(handshake&&) = default;
        handshake &operator=(handshake &&other) noexcept {
            if (this != &other) {
                this->hs_start_point = other.hs_start_point;
                this->retries = other.retries;
            }
            return *this;
        }

        [[nodiscard]]
        auto handle(const std::shared_ptr<host> &h, receive_event &e, const crypto::key_pair &pair) noexcept;

    private:
        std::chrono::steady_clock::time_point hs_start_point{std::chrono::steady_clock::now()};
        int retries{0};
    };
    class conn_confirm final : public state {
    public:
        inline static constinit auto max_duration = 250ms;
        constexpr conn_confirm() = default;

        constexpr conn_confirm(conn_confirm&&) = default;
        constexpr conn_confirm& operator=(conn_confirm&&) = default;

        [[nodiscard]]
        auto handle(const std::shared_ptr<host> &h, receive_event &e, const crypto::cipher &c) const noexcept;
    private:
        std::chrono::steady_clock::time_point confirm_start_point {std::chrono::steady_clock::now()};
    };
    class auth final : public state {
    public:
        constexpr auth() noexcept = default;

        [[nodiscard]]
        auto handle(const receive_event &e, const crypto::cipher &c) const noexcept;
    };
    class connected final : public state {
    public:
        constexpr connected() = default;

        constexpr connected(connected&&) = default;
        constexpr connected& operator=(connected&&) = default;

        [[nodiscard]]
        auto handle(const std::shared_ptr<host> &h, const receive_event &e, const crypto::cipher &c, const pty::session &session) const noexcept;
    };

    using state_t = std::variant<handshake, conn_confirm, auth, connected>;
    using transition_t = std::variant<keep_state_t, disconnect_t, establish_t, activate_session_t, state_t>;

    struct transition {
        static constexpr transition_t keep() noexcept { return {keep_state_t {}}; }
        static constexpr transition_t disconnect() noexcept { return {disconnect_t{}}; }
        static constexpr transition_t disconnect(std::string reason) noexcept {
            return {disconnect_t{std::move(reason)}};
        }
        static constexpr transition_t establish(crypto::cipher cipher) noexcept {
            return {establish_t{std::move(cipher)}};
        }
        static constexpr transition_t establish(std::unique_ptr<crypto::encryption> encryptor) noexcept {
            return {establish_t{crypto::cipher(std::move(encryptor))}};
        }
        static constexpr transition_t activate_session(std::string username, std::string passwd) noexcept {
            return {activate_session_t{std::move(username), std::move(passwd)}};
        }
        template <class T>
        requires std::derived_from<std::remove_cvref_t<T>, state> &&
            std::constructible_from<state_t, std::remove_cvref_t<T>>
        static constexpr transition_t to(T new_state) noexcept {
            return state_t(std::move(new_state));
        }
    };

    class peer_context {
    public:
        using host_ptr = std::shared_ptr<host>;

        constexpr peer_context(host_ptr host, state_t state, const crypto::key_pair &keys,
                               asio::io_context &ctx) noexcept :
            m_ctx(ctx), m_host(std::move(host)), state(std::move(state)), m_keys(keys) {}
        constexpr void handle(receive_event &e) noexcept;

        constexpr ~peer_context() noexcept {
            if (pump)
                pump->stop();
        }

    private:
        asio::io_context &m_ctx;
        host_ptr m_host;
        state_t state;
        crypto::key_pair m_keys;
        std::shared_ptr<crypto::cipher> cipher{nullptr};
        std::unique_ptr<pty::session> session{nullptr};
        std::shared_ptr<pty_pumper> pump{nullptr};
    };

    inline auto handshake::handle(const std::shared_ptr<host> &h, receive_event &e,
                                  const crypto::key_pair &pair) noexcept {
        if (std::chrono::steady_clock::now() - hs_start_point > max_duration) {
            return transition::disconnect("Timeout reached.");
        }
        const auto pkt = serial::packet_serializer::deserialize(u8_span_to_word_span(e.payload()));
        if (!pkt) [[unlikely]] {
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
        return transition::establish(crypto::cipher(std::move(encryptor)));
    }
    inline auto conn_confirm::handle(const std::shared_ptr<host> &h, receive_event &e,
                                     const crypto::cipher &c) const noexcept {
        if (std::chrono::steady_clock::now() - confirm_start_point > max_duration) {
            return transition::disconnect("Timeout reached.");
        }
        const auto decrypted = c.decrypt(e.payload());
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        const auto pkt = serial::packet_serializer::deserialize(u8_vector_to_word_span(*decrypted));
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }
        const auto *const sh_msg = std::get_if<shell_message>(&*pkt);
        if (!sh_msg || sh_msg->type != packet_type::BYTES) [[unlikely]] {
            return transition::keep();
        }
        if (!is_confirm<crypto::side::SERVER>(sh_msg->bytes)) {
            return transition::keep();
        }
        const auto s_pkt = shell_message{packet_type::BYTES,
                                         std::vector(s_confirm_magic, s_confirm_magic + sizeof(s_confirm_magic))};
        const auto words = serial::packet_serializer::serialize(s_pkt);
        const auto encrypted = c.encrypt(capnp_array_to_span(words));
        if (!encrypted) [[unlikely]] {
            return transition::keep();
        }
        if (!h->send(e.peer(), *encrypted)) {
            return transition::keep();
        }

        return transition::to(auth{});
    }
    // ReSharper disable once CppMemberFunctionMayBeStatic
    inline auto auth::handle(const receive_event &e, const crypto::cipher &c) const noexcept {
        const auto decrypted = c.decrypt(e.payload());
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        auto pkt = serial::packet_serializer::deserialize(u8_vector_to_word_span(*decrypted));
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }
        auto *const request = std::get_if<auth_packet>(&*pkt);
        if (!request) [[unlikely]] {
            return transition::keep();
        }

        return transition::activate_session(std::move(request->username), std::move(request->password));
    }
    // ReSharper disable once CppMemberFunctionMayBeStatic
    inline auto connected::handle(const std::shared_ptr<host> & /* h */, const receive_event &e,
                                  const crypto::cipher &c,
                                  const pty::session &session) const noexcept {
        const auto decrypted = c.decrypt(e.payload());
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        const auto pkt = serial::packet_serializer::deserialize(u8_vector_to_word_span(*decrypted));
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }

        return std::visit(overloaded {
            [&] (const shell_message &sh_msg) constexpr  {
                switch (sh_msg.type) {
                    case packet_type::BYTES: {
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
            [&] (const resize_packet &win_resize) constexpr {
                ioctl(session.fd(), TIOCSWINSZ, &win_resize.ws);
                return transition::keep();
            },
            [&] (auto &&) constexpr {return transition::keep();}
        }, *pkt);
    }
    constexpr void peer_context::handle(receive_event &e) noexcept {
        auto transition = std::visit<transition_t>(overloaded {
            [&] (handshake &s) constexpr {
                return s.dispatch(m_host, e, m_keys);
            },
            [&] (const conn_confirm &s) constexpr {
                return s.dispatch(m_host, e, *cipher);
            },
            [&] (const auth &s) constexpr {
                return s.dispatch(e, *cipher);
            },
            [&] (const connected &s) constexpr {
                return s.dispatch(m_host, e, *cipher, *session);
            }
        }, state);

        std::visit(overloaded {
            [] (keep_state_t &) constexpr {},
            [&] (const disconnect_t &d) constexpr {
                if (!this->m_host) [[unlikely]] {
                    return;
                }
                if (!d.reason.empty()) [[likely]] {
                    if (!this->cipher) [[unlikely]] {
                        goto disconnect;
                    }
                    const auto pkt = shell_message {packet_type::DISCONNECT, std::vector<u8>(d.reason.begin(), d.reason.end())};
                    const auto words = serial::packet_serializer::serialize(pkt);
                    const auto encrypted = cipher->encrypt(capnp_array_to_span(words));
                    if (!encrypted) [[unlikely]] {
                        goto disconnect;
                    }
                    this->m_host->send(e.peer(), *encrypted);
                }

                disconnect:
                this->m_host->disconnect(e.peer());
            },
            [&] (establish_t &est) constexpr {
                this->cipher = std::make_shared<crypto::cipher>(std::move(est.cipher));
                this->state = conn_confirm {};
            },
            [&] (const activate_session_t &act) constexpr {
                auto exp_sess = pty::session::create_unique(act.username, act.password);
                if (!exp_sess) {
                    spdlog::error("Failed to create pty session: {}", exp_sess.error());
                    const auto pkt = shell_message {packet_type::AUTH_RESPONSE, std::vector<u8> {exp_sess.error().begin(), exp_sess.error().end()}};
                    const auto words = serial::packet_serializer::serialize(pkt);
                    const auto encrypted = cipher->encrypt(capnp_array_to_span(words));
                    if (!encrypted) [[unlikely]] {
                        spdlog::error("Failed to encrypt error message: {}", encrypted.error());
                        goto disconnect;
                    }

                    this->m_host->send(e.peer(), *encrypted);
                    disconnect:
                    this->m_host->disconnect(e.peer());
                    return;
                }

                const auto data = std::vector<u8> {s_confirm_magic, s_confirm_magic + sizeof(s_confirm_magic)};
                const auto pkt = shell_message {packet_type::AUTH_RESPONSE, data};
                const auto words = serial::packet_serializer::serialize(pkt);
                const auto encrypted = cipher->encrypt(capnp_array_to_span(words));
                if (!encrypted) [[unlikely]] {
                    spdlog::error("Failed to encrypt confirmation message: {}", encrypted.error());
                    this->m_host->disconnect(e.peer());
                    return;
                }
                this->m_host->send(e.peer(), *encrypted);

                this->session = std::move(*exp_sess);
                this->pump = std::make_shared<pty_pumper>(
                    this->m_ctx,
                    this->session->fd(),
                    this->m_host.get(),
                    e.peer(),
                    *this->cipher
                    );
                this->pump->start();
                this->state = connected {};
            },
            [&] (state_t &new_state) constexpr {
                this->state = std::move(new_state);
            }
        }, transition);
    }
} // net



#endif //STATE_H
