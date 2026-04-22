//
// Created by inquaterni on 1/7/26.
//

#ifndef KEY_PAIR_H
#define KEY_PAIR_H
#include <expected>
#include <string>

#include "types.h"
#include "guard.h"

namespace crypto {

    class key_pair {
    public:
        static constexpr std::expected<key_pair, std::string> enroll() {
            if (!guard::is_initialized()) {
                return std::unexpected {"Libsodium is not initialized."};
            }

            pkey_t pub_key;
            skey_t sec_key;
            crypto_kx_keypair(pub_key.data(), sec_key.data());

            return key_pair {pub_key, sec_key};
        }

        consteval key_pair() noexcept = default;

        constexpr key_pair(const pkey_t& /* public key */,
                           const skey_t& /* secret key */) noexcept;

        [[nodiscard]]
        constexpr pkey_t &public_key() noexcept;
        [[nodiscard]]
        constexpr skey_t &secret_key() noexcept;
        [[nodiscard]]
        constexpr const pkey_t &cpublic_key() const noexcept;
        [[nodiscard]]
        constexpr const skey_t &csecret_key() const noexcept;

    private:
        pkey_t pub_key;
        skey_t sec_key;
    };
    constexpr key_pair::key_pair(const pkey_t &p_key, const skey_t &s_key) noexcept :
        pub_key(p_key), sec_key(s_key) {}

    constexpr pkey_t &key_pair::public_key() noexcept { return pub_key; }
    constexpr skey_t &key_pair::secret_key() noexcept { return sec_key; }
    constexpr const pkey_t &key_pair::cpublic_key() const noexcept { return pub_key; }
    constexpr const skey_t &key_pair::csecret_key() const noexcept { return sec_key; }

} // crypto

#endif //KEY_PAIR_H
