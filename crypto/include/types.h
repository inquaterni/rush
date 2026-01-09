//
// Created by inquaterni on 1/7/26.
//

#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H
#include <array>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_kx.h>

namespace crypto {
    using u8 = unsigned char;
    using u64 = unsigned long long;

    using pkey_t = std::array<u8, crypto_kx_PUBLICKEYBYTES>;
    using skey_t = std::array<u8, crypto_kx_SECRETKEYBYTES>;
    using session_key_t = std::array<u8, crypto_kx_SESSIONKEYBYTES>;
    constexpr u64 nonce_chacha20_size = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    using nonce_chacha20_t = std::array<u8, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>;
} // crypto

#endif //CRYPTO_TYPES_H
