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
#include "../include/session_keys.h"
#include <algorithm>
namespace crypto {
    session_keys::session_keys(const session_key_t &rx, const session_key_t &tx) noexcept
    : receive_key(rx), transmit_key(tx) {}
    session_keys::session_keys(session_key_t &&rx, session_key_t &&tx) noexcept
    : receive_key(std::forward<session_key_t>(rx)), transmit_key(std::forward<session_key_t>(tx)) {}
    session_keys::session_keys(const u8 *rx, const u8 *tx) noexcept
    : receive_key{}, transmit_key{} {
        std::copy_n(rx,  crypto_kx_SESSIONKEYBYTES, receive_key.begin());
        std::copy_n(tx,  crypto_kx_SESSIONKEYBYTES, transmit_key.begin());
    }
} // crypto
