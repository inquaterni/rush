//
// Created by inquaterni on 12/31/25.
//

#include "../include/secure_session.h"

#include <algorithm>


namespace enet {

    secure_session::secure_session(const session_key_t &rx, const session_key_t &tx) noexcept
    : receive_key(rx), transmit_key(tx) {}
    secure_session::secure_session(session_key_t &&rx, session_key_t &&tx) noexcept
    : receive_key(std::forward<session_key_t>(rx)), transmit_key(std::forward<session_key_t>(tx)) {}
    secure_session::secure_session(const u8 *rx, const u8 *tx) noexcept {
        std::copy_n(rx,  crypto_kx_SESSIONKEYBYTES, receive_key.begin());
        std::copy_n(tx,  crypto_kx_SESSIONKEYBYTES, transmit_key.begin());
    }
} // namespace enet