//
// Created by inquaterni on 1/7/26.
//

#ifndef SECURE_SESSION_FACTORY_H
#define SECURE_SESSION_FACTORY_H
#include "key_pair.h"
#include "session_keys.h"

namespace crypto {

    class keys_factory {
    public:
        static constexpr std::expected<key_pair, std::string> enroll_key_pair() {
            if (!guard::is_initialized()) {
                return std::unexpected {"Libsodium is not initialized."};
            }

            pkey_t pub_key;
            skey_t sec_key;
            crypto_kx_keypair(pub_key.data(), sec_key.data());

            return key_pair {pub_key, sec_key};
        }
        static constexpr std::expected<session_keys, std::string> enroll_sk_server(const key_pair &keys, const pkey_t &other_pub_key) {
            session_key_t rx;
            session_key_t tx;

            if (crypto_kx_server_session_keys(rx.data(), tx.data(),
                keys.cpublic_key().data(), keys.csecret_key().data(),
                other_pub_key.data()) != 0) [[unlikely]] {
                    return std::unexpected { "Connection is compromised." };
                }

            return session_keys {rx, tx};
        }
        static constexpr std::expected<session_keys, std::string> enroll_sk_client(const key_pair &keys, const pkey_t &other_pub_key) {
            session_key_t rx;
            session_key_t tx;

            if (crypto_kx_client_session_keys(rx.data(), tx.data(),
                keys.cpublic_key().data(), keys.csecret_key().data(),
                other_pub_key.data()) != 0) [[unlikely]] {
                    return std::unexpected { "Connection is compromised." };
                }

            return session_keys {rx, tx};
        }
    };

} // crypto

#endif //SECURE_SESSION_FACTORY_H
