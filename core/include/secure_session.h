//
// Created by inquaterni on 12/31/25.
//

#ifndef SECURE_SESSION_H
#define SECURE_SESSION_H
#include <array>
#include <sodium/crypto_kx.h>

#include "packet.h"


namespace enet {
    class secure_session {
    public:
        using session_key_t = std::array<u8, crypto_kx_SESSIONKEYBYTES>;
        secure_session(const session_key_t & /* rx */, const session_key_t & /* tx */) noexcept;
        secure_session(session_key_t && /* rx */, session_key_t && /* tx */) noexcept;

        secure_session(const u8 * /* rx */, const u8 * /* tx */) noexcept;
    private:
        session_key_t receive_key;
        session_key_t transmit_key;

        std::size_t tx_counter {0};
        std::size_t rx_counter {0};

    };
} // namespace enet



#endif //SECURE_SESSION_H
