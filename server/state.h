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
#include "xchacha20poly1305.h"

namespace net {
    using namespace std::chrono_literals;
    class state;
    class handshake;
    class conn_confirm;
    class connected;

    static constexpr u8 c_confirm_magic[] = "CONFIRM";
    static constexpr u8 s_confirm_magic[] = "OK";

    static bool is_c_confirm(const std::vector<u8>& data) {
        return data.size() == sizeof(c_confirm_magic) &&
               std::memcmp(data.data(), c_confirm_magic, sizeof(c_confirm_magic)) == 0;
    }
    static bool is_s_confirm(const std::vector<u8>& data) {
        return data.size() == sizeof(s_confirm_magic) &&
               std::memcmp(data.data(), s_confirm_magic, sizeof(s_confirm_magic)) == 0;
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

        auto handle(const std::shared_ptr<host> &h, receive_event &e) noexcept;

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

        auto handle(const std::shared_ptr<host> &h, receive_event &e) noexcept;
    private:
        std::chrono::steady_clock::time_point confirm_start_point {std::chrono::steady_clock::now()};
        crypto::cipher cipher_;
    };
    class connected final : public state {
    public:
        constexpr explicit connected(crypto::cipher &&c) noexcept
        : cipher_(std::forward<crypto::cipher>(c)) {}

        connected(connected&&) = default;
        connected& operator=(connected&&) = default;

        auto handle(const std::shared_ptr<host> &h, receive_event &e) noexcept;
    private:
        crypto::cipher cipher_;
    };

    using state_t = std::variant<handshake, conn_confirm, connected>;

    class peer_context {
    public:
        using host_ptr = std::shared_ptr<host>;

        peer_context(host_ptr host, state_t &&state) : m_host(std::move(host)), state(std::forward<state_t>(state)) {}
        constexpr void handle(receive_event &e) noexcept;

    private:
        host_ptr m_host;
        state_t state;
    };


    inline auto handshake::handle(const std::shared_ptr<host> &h, receive_event &e) noexcept {
        using return_type = std::optional<state_t>;
        if (std::chrono::steady_clock::now() - hs_start_point > max_handshake_duration) {
            return return_type{std::nullopt};
        }
        const auto words = std::span(reinterpret_cast<const capnp::word *>(e.payload().data()),
                                     e.payload().size() / sizeof(capnp::word));
        const auto pkt = serial::packet_serializer::deserialize(words);
        if (!pkt) [[unlikely]] {
            if (retries++ > max_retries) {
                return return_type{std::nullopt};
            }
            return return_type{std::move(*this)};
        }
        const auto *const hs = std::get_if<handshake_packet>(&*pkt);
        if (!hs) [[unlikely]] {
            if (retries++ > max_retries) {
                return return_type{std::nullopt};
            }
            return return_type{std::move(*this)};
        }
        const auto sk = crypto::keys_factory::enroll<crypto::side::SERVER>(pair, hs->public_key);
        if (!sk) [[unlikely]] {
            if (retries++ > max_retries) {
                return return_type{std::nullopt};
            }
            return return_type{std::move(*this)};
        }
        if (!h->send(e.peer(), handshake_packet{pair.cpublic_key()})) [[unlikely]] {
            if (retries++ > max_retries) {
                return return_type{std::nullopt};
            }

            return return_type{std::move(*this)};
        }

        auto encryptor = std::make_unique<crypto::xchacha20poly1305>(*sk);
        return return_type{conn_confirm{std::move(encryptor)}};
    }
    inline auto conn_confirm::handle(const std::shared_ptr<host> &h, receive_event &e) noexcept {
        using return_type = std::optional<state_t>;
        if (std::chrono::steady_clock::now() - confirm_start_point > max_confirmation_duration) {
            return return_type{std::nullopt};
        }

        const auto words = std::span(reinterpret_cast<const capnp::word *>(e.payload().data()),
                                     e.payload().size() / sizeof(capnp::word));
        const auto pkt = serial::packet_serializer::deserialize(words);
        if (!pkt) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto *const g_pkt = std::get_if<generic_packet>(&*pkt);
        if (!g_pkt || g_pkt->type != packet_type::XCHACHA20POLY1305) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto decrypted = cipher_.decrypt(g_pkt->body);
        if (!decrypted) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto original = pack::compressor::decompress(*decrypted);
        if (!original) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        if (!is_c_confirm(*original)) {
            return return_type{std::move(*this)};
        }
        const auto compressed = pack::compressor::compress(std::span{s_confirm_magic, sizeof(s_confirm_magic)});
        if (!compressed) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto encrypted = cipher_.encrypt(*compressed);
        if (!encrypted) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        if (!h->send(e.peer(), generic_packet{packet_type::XCHACHA20POLY1305, *encrypted})) {
            return return_type{std::move(*this)};
        }

        return return_type{connected{std::move(cipher_)}};
    }
    inline auto connected::handle(const std::shared_ptr<host> &h, receive_event &e) noexcept {
        using return_type = std::optional<state_t>;
        const auto words = std::span(reinterpret_cast<const capnp::word *>(e.payload().data()),
                                     e.payload().size() / sizeof(capnp::word));
        const auto pkt = serial::packet_serializer::deserialize(words);
        if (!pkt) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto *const g_pkt = std::get_if<generic_packet>(&*pkt);
        if (!g_pkt || g_pkt->type != packet_type::XCHACHA20POLY1305) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto decrypted = cipher_.decrypt(g_pkt->body);
        if (!decrypted) [[unlikely]] {
            return return_type{std::move(*this)};
        }
        const auto original = pack::compressor::decompress(*decrypted);
        if (!original) [[unlikely]] {
            return return_type{std::move(*this)};
        }

        const auto str = std::string_view{reinterpret_cast<const char *>(original->data()), original->size()};
        spdlog::info("Received message: {}", str);

        return return_type{std::move(*this)};
    }
    constexpr void peer_context::handle(receive_event &e) noexcept {
        auto next_state = std::visit<std::optional<state_t>>(overloaded {
            [&] (auto &s) {
                return s.handle(m_host, e);
            }
        }, state);

        if (!next_state) return;
        state = std::move(*next_state);
    }
} // net



#endif //STATE_H
