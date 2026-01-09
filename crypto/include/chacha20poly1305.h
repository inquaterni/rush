//
// Created by inquaterni on 1/8/26.
//

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H
#include <expected>
#include <sodium/randombytes.h>
#include <span>
#include <string>
#include <vector>

#include "guard.h"
#include "secure_session.h"
#include "types.h"


namespace crypto {
    class encryption {
    public:
        encryption() = default;
        explicit encryption(const secure_session &ss) noexcept;
        explicit encryption(secure_session &&ss) noexcept;

        virtual ~encryption() = default;

        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::span<const u8> & /* message */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::vector<u8> & /* message */) = 0;

        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::span<const u8> & /* encrypted */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::vector<u8> & /* encrypted */) = 0;
    };
    class chacha20poly1305 final : public encryption {
        public:
        explicit constexpr chacha20poly1305(const secure_session &ss) noexcept;
        explicit constexpr chacha20poly1305(secure_session &&ss) noexcept;
        ~chacha20poly1305() override = default;
        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::span<const u8> & ) override;
        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::vector<u8> &) override;

        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::span<const u8> & ) override;
        [[nodiscard]] constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::vector<u8> &) override;

    private:
        constexpr static u64 nonce_len = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
        constexpr static u64 mac_len = crypto_aead_chacha20poly1305_ietf_ABYTES;

        secure_session ss;
    };

    constexpr chacha20poly1305::chacha20poly1305(const secure_session &ss) noexcept : ss {ss} {}
    constexpr chacha20poly1305::chacha20poly1305(secure_session &&ss) noexcept : ss {std::forward<secure_session>(ss)} {}

    constexpr std::expected<std::vector<u8>, std::string> chacha20poly1305::encrypt(const std::span<const u8> &message) {

        if (!guard::is_initialized()) {
            return std::unexpected { "Sodium is not initialized." };
        }
        std::vector<u8> encrypted {};
        encrypted.resize(message.size() + nonce_len + mac_len);

        randombytes_buf(encrypted.data(), nonce_len);

        u64 ciphertext_len;
        const int err = crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted.data() + nonce_len, &ciphertext_len,
            message.data(), message.size(),
            nullptr, 0,
            nullptr, encrypted.data(),
            ss.tx().data()
            );

        if (err != 0) {
            return std::unexpected { "Sodium encryption failed." };
        }

        return encrypted;
    }
    constexpr std::expected<std::vector<u8>, std::string> chacha20poly1305::encrypt(const std::vector<u8> &message) {
        if (!guard::is_initialized()) {
            return std::unexpected { "Sodium is not initialized." };
        }
        std::vector<u8> encrypted {};
        encrypted.resize(message.size() + nonce_len + mac_len);

        randombytes_buf(encrypted.data(), nonce_len);

        u64 ciphertext_len;
        const int err = crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted.data() + nonce_len, &ciphertext_len,
            message.data(), message.size(),
            nullptr, 0,
            nullptr, encrypted.data(),
            ss.tx().data()
            );

        if (err != 0) {
            return std::unexpected { "Sodium encryption failed." };
        }

        return encrypted;
    }

    constexpr std::expected<std::vector<u8>, std::string> chacha20poly1305::decrypt(const std::span<const u8> &cipher) {
        if (!guard::is_initialized()) {
            return std::unexpected { "Sodium is not initialized." };
        }
        if (cipher.size() < nonce_len + mac_len) {
            return std::unexpected { "Ciphertext is too small." };
        }
        const u8 *nonce = cipher.data();
        const u8 *ciphertext = cipher.data() + nonce_len;
        const u64 ciphertext_len = cipher.size() - nonce_len;
        std::vector<u8> decrypted {};
        decrypted.resize(ciphertext_len - mac_len);
        u64 decrypted_len;

        const int err = crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr, ciphertext, ciphertext_len,
            nullptr, 0,
            nonce, ss.rx().data());
        if (err != 0) {
            return std::unexpected { "Sodium decryption failed." };
        }

        return decrypted;
    }
    constexpr std::expected<std::vector<u8>, std::string> chacha20poly1305::decrypt(const std::vector<u8> &cipher) {
        if (!guard::is_initialized()) {
            return std::unexpected { "Sodium is not initialized." };
        }
        if (cipher.size() < nonce_len + mac_len) {
            return std::unexpected { "Ciphertext is too small." };
        }
        const u8 *nonce = cipher.data();
        const u8 *ciphertext = cipher.data() + nonce_len;
        const u64 ciphertext_len = cipher.size() - nonce_len;
        std::vector<u8> decrypted {};
        decrypted.resize(ciphertext_len - mac_len);
        u64 decrypted_len;

        const int err = crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr, ciphertext, ciphertext_len,
            nullptr, 0,
            nonce, ss.rx().data());
        if (err != 0) {
            return std::unexpected { "Sodium decryption failed." };
        }

        return decrypted;
    }
} // crypto



#endif //CHACHA20POLY1305_H
