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
                                                  connection_data *data) noexcept;

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
        const auto words = std::span(reinterpret_cast<const capnp::word *>(e.payload().data()),
                                     e.payload().size() / sizeof(capnp::word));
        const auto pkt = serial::packet_serializer::deserialize(words);
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

        const auto words = std::span(reinterpret_cast<const capnp::word *>(e.payload().data()),
                                     e.payload().size() / sizeof(capnp::word));
        const auto pkt = serial::packet_serializer::deserialize(words);
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }
        const auto *const g_pkt = std::get_if<generic_packet>(&*pkt);
        if (!g_pkt || g_pkt->type != packet_type::XCHACHA20POLY1305) [[unlikely]] {
            return transition::keep();
        }
        const auto decrypted = cipher_.decrypt(g_pkt->body);
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        const auto original = pack::compressor::decompress(*decrypted);
        if (!original) [[unlikely]] {
            return transition::keep();
        }
        if (!is_confirm<crypto::side::SERVER>(*original)) {
            return transition::keep();
        }
        const auto compressed = pack::compressor::compress(std::span{s_confirm_magic, sizeof(s_confirm_magic)});
        if (!compressed) [[unlikely]] {
            return transition::keep();
        }
        const auto encrypted = cipher_.encrypt(*compressed);
        if (!encrypted) [[unlikely]] {
            return transition::keep();
        }
        if (!h->send(e.peer(), generic_packet{packet_type::XCHACHA20POLY1305, *encrypted})) {
            return transition::keep();
        }

        return transition::to(connected{std::move(cipher_), h, e.peer(), pty});
    }
    inline auto connected::handle(const std::shared_ptr<host> & /* h */, const receive_event &e,
                                  const pty::session &session) const noexcept {
        const auto words = std::span(reinterpret_cast<const capnp::word *>(e.payload().data()),
                                     e.payload().size() / sizeof(capnp::word));
        const auto pkt = serial::packet_serializer::deserialize(words);
        if (!pkt) [[unlikely]] {
            return transition::keep();
        }
        const auto *const g_pkt = std::get_if<generic_packet>(&*pkt);
        if (!g_pkt || g_pkt->type != packet_type::XCHACHA20POLY1305) [[unlikely]] {
            return transition::keep();
        }
        const auto decrypted = data_->cipher.decrypt(g_pkt->body);
        if (!decrypted) [[unlikely]] {
            return transition::keep();
        }
        const auto original = pack::compressor::decompress(*decrypted);
        if (!original) [[unlikely]] {
            return transition::keep();
        }

        if (!original->empty()) {
            if (!session.write(*original)) {
                spdlog::error("Failed to write.");
                return transition::keep();
            }
        }

        return transition::keep();
    }
    constexpr void connected::pump_pty_to_network(const std::stop_token &st,
                                                  const pty::session &session, connection_data *data) noexcept {
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
                const auto raw = std::span<const u8> {reinterpret_cast<u8 *>(buffer.data()), n};
                const auto compressed = pack::compressor::compress(raw);
                if (!compressed) [[unlikely]] continue;
                const auto encrypted = data->cipher.encrypt(*compressed);
                if (!encrypted) [[unlikely]] continue;
                if (!data->host_) break;
                if (!data->peer) break;
                data->host_->send(data->peer, generic_packet{packet_type::XCHACHA20POLY1305, *encrypted});
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
