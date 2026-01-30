//
// Created by inquaterni on 1/21/26.
//

#ifndef STATE_H
#define STATE_H
#include <memory>

#include "tunnel_session.h"
#include "client.h"
#include "guard.h"
#include "key_pair.h"
#include "keys_factory.h"
#include "xchacha20poly1305.h"

namespace crypto {
    enum class side : u8;
}
namespace net {
    using namespace std::chrono_literals;

    struct keep_state_t {};
    struct activate_session_t {};
    struct disconnect_t {
        std::string reason {};
    };
    struct establish_t {
        crypto::cipher cipher;
    };

    class state;
    class init;
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
        auto handle(const std::shared_ptr<client> &c, const receive_event& e, const crypto::key_pair &pair) noexcept;
    private:
        std::chrono::steady_clock::time_point hs_start_point{std::chrono::steady_clock::now()};
        int retries{0};
    };
    class conn_confirm final : public state {
    public:
        inline static constinit auto max_duration = 250ms;
        constexpr conn_confirm() noexcept = default;

        constexpr conn_confirm(conn_confirm&&) = default;
        constexpr conn_confirm& operator=(conn_confirm&&) = default;

        [[nodiscard]]
        auto handle(const std::shared_ptr<client> &c, const receive_event &e, const crypto::cipher &cipher, std::string_view user) const noexcept;
    private:
        std::chrono::steady_clock::time_point confirm_start_point {std::chrono::steady_clock::now()};
    };
    class auth final : public state {
    public:
        static constinit inline int max_retries {1};
        constexpr auth() noexcept = default;

        [[nodiscard]]
        auto handle(const std::shared_ptr<client> &c, const receive_event &e, const crypto::cipher &cipher,
                    std::string_view user) noexcept;
    private:
        int retries{0};
    };
    class connected final : public state {
    public:
        constexpr connected() = default;

        constexpr connected(connected&&) = default;
        constexpr connected& operator=(connected&&) = default;

        [[nodiscard]]
        auto handle(const std::shared_ptr<client> &c, const receive_event &e,
                    const crypto::cipher &cipher) const noexcept;
    };

    using state_t = std::variant<handshake, conn_confirm, auth, connected>;
    using transition_t = std::variant<keep_state_t, disconnect_t, establish_t, activate_session_t, state_t>;

    struct transition {
        static constexpr transition_t keep() noexcept { return {keep_state_t {}}; }
        static constexpr transition_t disconnect() noexcept { return {disconnect_t{}}; }
        static constexpr transition_t disconnect(std::string reason) noexcept {
            return {disconnect_t{std::move(reason)}};
        }
        static constexpr transition_t disconnect(const std::vector<u8> &bytes) noexcept {
            std::string reason(bytes.begin(), bytes.end());
            return {disconnect_t{std::move(reason)}};
        }
        static constexpr transition_t establish(crypto::cipher cipher) noexcept {
            return {establish_t{std::move(cipher)}};
        }
        static constexpr transition_t establish(std::unique_ptr<crypto::encryption> encryptor) noexcept {
            return {establish_t{crypto::cipher(std::move(encryptor))}};
        }
        static constexpr transition_t activate_session() noexcept { return {activate_session_t{}}; }
        template <class T>
        requires std::derived_from<std::remove_cvref_t<T>, state> &&
            std::constructible_from<state_t, std::remove_cvref_t<T>>
        static constexpr transition_t to(T new_state) noexcept {
            return state_t(std::move(new_state));
        }
    };

    class client_context {
    public:
        using client_ptr = std::shared_ptr<client>;

        constexpr client_context(client_ptr host, state_t state, const crypto::key_pair &keys,
                                 asio::io_context &ctx,
                                 const std::string_view username, asio::signal_set &sigset) noexcept :
            m_ctx(ctx), m_client(std::move(host)), state(std::move(state)), m_keys(keys), signals(sigset), m_username(username) {}
        constexpr void handle(receive_event &e) noexcept;

        constexpr ~client_context() noexcept {
            if (m_sess) m_sess->stop();
        }

    private:
        asio::io_context &m_ctx;
        client_ptr m_client;
        state_t state;
        crypto::key_pair m_keys;
        asio::signal_set &signals;
        term::guard &m_guard{term::guard::get_instance()};
        std::string_view m_username;
        std::shared_ptr<crypto::cipher> cipher {nullptr};
        std::shared_ptr<tunnel::tunnel_session> m_sess {nullptr};
    };
    inline auto handshake::handle(const std::shared_ptr<client> &c, const receive_event &e,
                           const crypto::key_pair &pair) noexcept {
        if (std::chrono::steady_clock::now() - hs_start_point > max_duration) {
            return transition::disconnect("Timeout reached.");
        }

        const auto pkt = serial::packet_serializer::deserialize(u8_span_to_word_span(e.payload()));
        if (!pkt) {
            return transition::keep();
        }
        return std::visit(overloaded {
            [&] (const handshake_packet &hs) constexpr {
                const auto sk = crypto::keys_factory::enroll<crypto::side::CLIENT>(pair, hs.public_key);
                if (!sk) [[unlikely]] {
                    if (retries++ > max_retries) {
                        return transition::disconnect("Maximum retries exceeded.");
                    }
                    return transition::keep();
                }

                auto encryptor = std::make_unique<crypto::xchacha20poly1305>(*sk);
                auto cipher = crypto::cipher(std::move(encryptor));

                const auto confirm = shell_message{packet_type::BYTES,
                                                   std::vector(c_confirm_magic, c_confirm_magic + sizeof(c_confirm_magic))};
                const auto encrypted = cipher.encrypt(capnp_array_to_span(serial::packet_serializer::serialize(confirm)));
                if (!encrypted) [[unlikely]] {
                    if (retries++ > max_retries) {
                        return transition::disconnect("Maximum retries exceeded.");
                    }

                    return transition::keep();
                }
                if (!c->send(*encrypted)) [[unlikely]] {
                    if (retries++ > max_retries) {
                        return transition::disconnect("Maximum retries exceeded.");
                    }

                    return transition::keep();
                }

                return transition::establish(std::move(cipher));
            },
            [&] (const shell_message &sh_msg) constexpr {
                if (sh_msg.type != packet_type::DISCONNECT) {
                    if (retries++ > max_retries) {
                        return transition::disconnect("Maximum retries exceeded.");
                    }
                    return transition::keep();
                }

                return transition::disconnect(sh_msg.bytes);
            },
            [&] (auto &) constexpr {
                if (retries++ > max_retries) {
                    return transition::disconnect("Maximum retries exceeded.");
                }
                return transition::keep();
            }
        }, *pkt);
    }
    inline auto conn_confirm::handle(const std::shared_ptr<client> &c, const receive_event &e,
                                     const crypto::cipher &cipher, const std::string_view user) const noexcept {
        if (std::chrono::steady_clock::now() - confirm_start_point > max_duration) {
            return transition::disconnect("Timeout reached.");
        }
        const auto decrypted = cipher.decrypt(e.payload());
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
                    case packet_type::BYTES: {
                        if (!is_confirm<crypto::side::CLIENT>(sh_msg.bytes)) {
                            return transition::keep();
                        }

                        auto pwd = term::getpwd(std::format("{}'s password: ", user));
                        if (!pwd) [[unlikely]] {
                            return transition::disconnect(pwd.error());
                        }
                        const auto auth_request = auth_packet{std::string(user), std::move(*pwd)};
                        const auto words = serial::packet_serializer::serialize(auth_request);
                        const auto encrypted = cipher.encrypt(capnp_array_to_span(words));
                        if (!encrypted) [[unlikely]] {
                            return transition::keep();
                        }
                        if (!c->send(*encrypted)) {
                            return transition::keep();
                        }

                        return transition::to(auth{});
                    }
                    case packet_type::DISCONNECT: {
                        return transition::disconnect(sh_msg.bytes);
                    }
                    default: return transition::keep();
                }
            },
            [&] (auto &) constexpr {
                return transition::keep();
            }
        }, *pkt);
    }
    // ReSharper disable once CppMemberFunctionMayBeStatic
    inline auto auth::handle(const std::shared_ptr<client> &c, const receive_event &e, const crypto::cipher &cipher, const std::string_view user) noexcept {
        const auto decrypted = cipher.decrypt(e.payload());
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
                    case packet_type::AUTH_RESPONSE: {
                        if (!is_confirm<crypto::side::CLIENT>(sh_msg.bytes)) {
                            spdlog::info(std::string{sh_msg.bytes.begin(), sh_msg.bytes.end()});
                            if (retries++ > max_retries) {
                                return transition::disconnect("Maximum retries exceeded.");
                            }
                            spdlog::info("Try again.");
                            auto pwd = term::getpwd(std::format("{}'s password: ", user));
                            if (!pwd) [[unlikely]] {
                                return transition::disconnect(pwd.error());
                            }
                            const auto auth_request = auth_packet{std::string(user), std::move(*pwd)};
                            const auto words = serial::packet_serializer::serialize(auth_request);
                            const auto encrypted = cipher.encrypt(capnp_array_to_span(words));
                            if (!encrypted) [[unlikely]] {
                                return transition::keep();
                            }
                            if (!c->send(*encrypted)) {
                                return transition::keep();
                            }

                            return transition::keep();
                        }
                        const auto ws = tunnel::tunnel_session::get_window_size();
                        if (!ws) [[unlikely]] {
                            spdlog::warn("Failed to retrieve window size.");
                            return transition::activate_session();
                        }
                        const auto resize = resize_packet {*ws};
                        const auto serialized = serial::packet_serializer::serialize(resize);
                        const auto encrypted = cipher.encrypt(capnp_array_to_span(serialized));
                        if (!encrypted) [[unlikely]] {
                            spdlog::warn("Failed to encrypt window size data.");
                            return transition::activate_session();
                        }
                        if (!c->send(*encrypted, 1)) {
                            spdlog::warn("Failed to send encrypted data.");
                            return transition::activate_session();
                        }

                        return transition::activate_session();
                    }
                    case packet_type::DISCONNECT: {
                        return transition::disconnect(sh_msg.bytes);
                    }
                    default: return transition::keep();
                }
            },
            [&] (auto &) constexpr {
                return transition::keep();
            }
        }, *pkt);
    }
    // ReSharper disable once CppMemberFunctionMayBeStatic
    inline auto connected::handle(const std::shared_ptr<client> &, const receive_event &e,
                                  const crypto::cipher &cipher) const noexcept {
        const auto decrypted = cipher.decrypt(e.payload());
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
                            write(STDOUT_FILENO, sh_msg.bytes.data(), sh_msg.bytes.size());
                        }
                    } break;
                    case packet_type::DISCONNECT: {
                        transition::disconnect(sh_msg.bytes);
                    } break;
                    default: return transition::keep();
                }

                return transition::keep();

            },
            [&] (auto &&) constexpr {return transition::keep();}
        }, *pkt);
    }

    constexpr void client_context::handle(receive_event &e) noexcept {
        auto transition = std::visit<transition_t>(overloaded {
            [&] (connected &s) constexpr {
                return s.dispatch(m_client, e, *cipher);
            },
            [&] (auth &s) constexpr {
                return s.dispatch(m_client, e, *cipher, this->m_username);
            },
            [&] (conn_confirm &s) constexpr {
                return s.dispatch(m_client, e, *cipher, this->m_username);
            },
            [&] (handshake &s) constexpr {
                return s.dispatch(m_client, e, m_keys);
            }
        }, state);

        std::visit(overloaded {
            [&] (keep_state_t &) constexpr {},
            [&] (const disconnect_t &d) constexpr {
                if (!this->m_client) [[unlikely]] {
                    return;
                }
                if (!d.reason.empty()) [[likely]] {
                    spdlog::error("Disconnected from server: {}", d.reason);
                }
                if (this->m_guard.is_raw()) this->m_guard.disable_raw_mode();
                if (this->m_sess) this->m_sess->stop();

                this->m_client->disconnect();
            },
            [&] (establish_t &est) constexpr {
                spdlog::info("Successfully established secure connection.");
                this->cipher = std::make_shared<crypto::cipher>(std::move(est.cipher));
                this->state = conn_confirm {};
            },
            [&] (activate_session_t &) constexpr {
                if (!this->m_guard.enable_raw_mode()) {
                    spdlog::error("Failed to enable raw mode.");
                    this->m_client->disconnect();
                }

                this->m_sess = std::make_shared<tunnel::tunnel_session>(
                    this->m_ctx,
                    this->m_client,
                    *this->cipher,
                    this->signals
                    );

                this->m_sess->start();
                this->state = connected {};
            },
            [&] (state_t &new_state) constexpr {
                this->state = std::move(new_state);
            }
        }, transition);
    }

} // net

#endif //STATE_H
