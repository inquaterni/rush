//
// Created by inquaterni on 1/7/26.
//

#ifndef CIPHER_H
#define CIPHER_H
#include <expected>
#include <memory>
#include <sodium/randombytes.h>
#include <span>
#include <string>
#include <vector>


#include "chacha20poly1305.h"
#include "guard.h"
#include "secure_session.h"

namespace crypto {
    class cipher {
    public:
        explicit cipher(std::unique_ptr<encryption> &&encryption) noexcept
        : encryptor(std::forward<std::unique_ptr<class encryption>>(encryption)) {};

        [[nodiscard]]
        constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::span<const u8> &message) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->encrypt(message);
        }
        [[nodiscard]]
        constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::vector<u8> &message) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->encrypt(message);
        }
        [[nodiscard]]
        constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::span<const u8> &cipher) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->decrypt(cipher);
        }
        [[nodiscard]]
        constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::vector<u8> &cipher) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->decrypt(cipher);
        }

    private:
        std::unique_ptr<encryption> encryptor;
    };

} // crypto

#endif //CIPHER_H
