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
#ifndef CIPHER_H
#define CIPHER_H
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include "encryption.h"
#include "session_keys.h"
namespace crypto {
    class cipher {
    public:
        explicit cipher(std::unique_ptr<encryption> &&encryption) noexcept
        : encryptor(std::forward<std::unique_ptr<class encryption>>(encryption)) {};
#if defined(TESTING)
        virtual ~cipher() = default;
#endif
        [[nodiscard]]
        constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::span<const u8> &message) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->encrypt(message);
        }
        [[nodiscard]]
        constexpr std::expected<std::unique_ptr<std::vector<u8>, void (*)(std::vector<u8> *)>, std::string> encrypt_inplace(const std::span<const u8> &message) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->encrypt_inplace(message);
        }
        [[nodiscard]]
        constexpr std::expected<std::span<u8>, std::string> decrypt_inplace(const std::span<u8> &message) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->decrypt_inplace(message);
        }
        [[nodiscard]]
        constexpr std::expected<std::shared_ptr<std::vector<u8>>, std::string> decrypt_inplace(const std::span<const u8> &message) const {
            if (!encryptor) {
                return std::unexpected { "Encryptor pointer is null" };
            }
            return encryptor->decrypt_inplace(message);
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
    protected:
        std::unique_ptr<encryption> encryptor;
    };
} // crypto
#endif //CIPHER_H
