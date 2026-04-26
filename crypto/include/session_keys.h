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
#ifndef SECURE_SESSION_H
#define SECURE_SESSION_H
#include <expected>
#include <string>
#include "types.h"
#include "key_pair.h"
namespace crypto {
    class session_keys {
    public:
        static constexpr std::expected<session_keys, std::string> enroll_server(const key_pair &keys, const pkey_t &other_pub_key) {
            session_key_t rx;
            session_key_t tx;
            if (crypto_kx_server_session_keys(rx.data(), tx.data(),
                keys.cpublic_key().data(), keys.csecret_key().data(),
                other_pub_key.data()) != 0) [[unlikely]] {
                    return std::unexpected { "Connection is compromised." };
                }
            return session_keys {rx, tx};
        }
        static constexpr std::expected<session_keys, std::string> enroll_client(const key_pair &keys, const pkey_t &other_pub_key) {
            session_key_t rx;
            session_key_t tx;
            if (crypto_kx_client_session_keys(rx.data(), tx.data(),
                keys.cpublic_key().data(), keys.csecret_key().data(),
                other_pub_key.data()) != 0) [[unlikely]] {
                    return std::unexpected { "Connection is compromised." };
                }
            return session_keys {rx, tx};
        }
        session_keys(const session_key_t & /* rx */, const session_key_t & /* tx */) noexcept;
        session_keys(session_key_t && /* rx */, session_key_t && /* tx */) noexcept;
        session_keys(const u8 * /* rx */, const u8 * /* tx */) noexcept;
        [[nodiscard]] constexpr session_key_t const &tx() const noexcept { return transmit_key; }
        [[nodiscard]] constexpr session_key_t const &rx() const noexcept { return receive_key; }
    private:
        session_key_t receive_key;
        session_key_t transmit_key;
    };
} // crypto
#endif //SECURE_SESSION_H
