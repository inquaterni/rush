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
#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include <expected>
#include <span>
#include <string>
#include <vector>
#include "session_keys.h"
namespace crypto {
    class encryption {
    public:
        encryption() = default;
        explicit encryption(const session_keys &ss) noexcept;
        explicit encryption(session_keys &&ss) noexcept;
        virtual ~encryption() = default;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::span<const u8> & /* message */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> encrypt(const std::vector<u8> & /* message */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::unique_ptr<std::vector<u8>, void (*)(std::vector<u8> *)>,
                                                      std::string>
        encrypt_inplace(const std::span<const u8> & /* message */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::span<const u8> & /* encrypted */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::span<u8>, std::string> decrypt_inplace(const std::span<u8> & /* encrypted */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::shared_ptr<std::vector<u8>>, std::string> decrypt_inplace(const std::span<const u8> & /* encrypted */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::vector<u8> & /* encrypted */) = 0;
    };
} // crypto
#endif //ENCRYPTION_H
