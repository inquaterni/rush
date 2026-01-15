//
// Created by inquaterni on 1/11/26.
//

#ifndef XCHACHA20POLY1305_H
#define XCHACHA20POLY1305_H
#include <guard.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/randombytes.h>


#include "encryption.h"
#include "guard.h"


namespace crypto {
    class xchacha20poly1305 final : public encryption {
    public:
        explicit constexpr xchacha20poly1305(const session_keys &ss) noexcept;
        explicit constexpr xchacha20poly1305(session_keys &&ss) noexcept;

        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::span<const u8> &) override;
        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::vector<u8> &) override;

        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::span<const u8> &) override;
        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::vector<u8> &) override;

    private:
        constexpr static u64 nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        constexpr static u64 mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;

        session_keys ss;
    };
    constexpr xchacha20poly1305::xchacha20poly1305(const session_keys &ss) noexcept: ss {ss} {}
    constexpr xchacha20poly1305::xchacha20poly1305(session_keys &&ss) noexcept :
        ss{std::forward<session_keys>(ss)} {}

    constexpr std::expected<std::vector<u8>, std::string> xchacha20poly1305::encrypt(const std::span<const u8> &message) {
        if (!guard::is_initialized()) {
            return std::unexpected{"Sodium is not initialized."};
        }
        std::vector<u8> encrypted{};
        encrypted.resize(message.size() + nonce_len + mac_len);

        randombytes_buf(encrypted.data(), nonce_len);

        u64 ciphertext_len;
        const int err = crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted.data() + nonce_len, &ciphertext_len,
                                                                   message.data(), message.size(), nullptr, 0, nullptr,
                                                                   encrypted.data(), ss.tx().data());

        if (err != 0) {
            return std::unexpected{"Sodium encryption failed."};
        }
        encrypted.resize(nonce_len + ciphertext_len);

        return encrypted;
    }
    constexpr std::expected<std::vector<u8>, std::string> xchacha20poly1305::encrypt(const std::vector<u8> &message) {
        if (!guard::is_initialized()) {
            return std::unexpected{"Sodium is not initialized."};
        }
        std::vector<u8> encrypted{};
        encrypted.resize(message.size() + nonce_len + mac_len);

        randombytes_buf(encrypted.data(), nonce_len);

        u64 ciphertext_len;
        const int err = crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted.data() + nonce_len, &ciphertext_len,
                                                                   message.data(), message.size(), nullptr, 0, nullptr,
                                                                   encrypted.data(), ss.tx().data());

        if (err != 0) {
            return std::unexpected{"Sodium encryption failed."};
        }
        encrypted.resize(nonce_len + ciphertext_len);

        return encrypted;
    }

    constexpr std::expected<std::vector<u8>, std::string> xchacha20poly1305::decrypt(const std::span<const u8> &cipher) {
        if (!guard::is_initialized()) {
            return std::unexpected{"Sodium is not initialized."};
        }
        if (cipher.size() < nonce_len + mac_len) {
            return std::unexpected{"Ciphertext is too small."};
        }
        const u8 *nonce = cipher.data();
        const u8 *ciphertext = cipher.data() + nonce_len;
        const u64 ciphertext_len = cipher.size() - nonce_len;
        std::vector<u8> decrypted{};
        decrypted.resize(ciphertext_len - mac_len);
        u64 decrypted_len;

        const int err = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data(), &decrypted_len, nullptr, ciphertext,
                                                                  ciphertext_len, nullptr, 0, nonce, ss.rx().data());
        if (err != 0) {
            return std::unexpected{"Sodium decryption failed."};
        }

        return decrypted;
    }
    constexpr std::expected<std::vector<u8>, std::string> xchacha20poly1305::decrypt(const std::vector<u8> &cipher) {
        if (!guard::is_initialized()) {
            return std::unexpected{"Sodium is not initialized."};
        }
        if (cipher.size() < nonce_len + mac_len) {
            return std::unexpected{"Ciphertext is too small."};
        }
        const u8 *nonce = cipher.data();
        const u8 *ciphertext = cipher.data() + nonce_len;
        const u64 ciphertext_len = cipher.size() - nonce_len;
        std::vector<u8> decrypted{};
        decrypted.resize(ciphertext_len - mac_len);
        u64 decrypted_len;

        const int err = crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data(), &decrypted_len, nullptr, ciphertext,
                                                                  ciphertext_len, nullptr, 0, nonce, ss.rx().data());
        if (err != 0) {
            return std::unexpected{"Sodium decryption failed."};
        }

        return decrypted;
    }
} // crypto



#endif //XCHACHA20POLY1305_H
