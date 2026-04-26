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
    constexpr static u64 nonce_chacha20_size = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    using nonce_chacha20_t = std::array<u8, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>;
} // crypto
#endif //CRYPTO_TYPES_H
