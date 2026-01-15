//
// Created by inquaterni on 1/7/26.
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