//
// Created by inquaterni on 1/7/26.
//

#ifndef SECURE_SESSION_FACTORY_H
#define SECURE_SESSION_FACTORY_H
#include "key_pair.h"
#include "session_keys.h"

namespace crypto {

    enum class side: u8 {
        SERVER,
        CLIENT
    };

    class keys_factory {
    public:
        template<side s>
        static constexpr std::expected<session_keys, std::string> enroll(const key_pair &keys, const pkey_t &other_pub_key) {
            session_key_t rx;
            session_key_t tx;

            if constexpr (s == side::SERVER) {
                if (crypto_kx_server_session_keys(rx.data(), tx.data(),
                    keys.cpublic_key().data(), keys.csecret_key().data(),
                    other_pub_key.data()) != 0) [[unlikely]] {
                        return std::unexpected { "Connection is compromised." };
                    }
            } else {
                if (crypto_kx_client_session_keys(rx.data(), tx.data(),
                    keys.cpublic_key().data(), keys.csecret_key().data(),
                    other_pub_key.data()) != 0) [[unlikely]] {
                        return std::unexpected { "Connection is compromised." };
                    }
            }

            return session_keys {rx, tx};
        }
        // private:
    };

} // crypto

#endif //SECURE_SESSION_FACTORY_H
