//
// Created by inquaterni on 1/7/26.
//

#ifndef SECURE_SESSION_H
#define SECURE_SESSION_H
#include "types.h"

namespace crypto {

    class secure_session {
    public:
        secure_session(const session_key_t & /* rx */, const session_key_t & /* tx */) noexcept;
        secure_session(session_key_t && /* rx */, session_key_t && /* tx */) noexcept;

        secure_session(const u8 * /* rx */, const u8 * /* tx */) noexcept;

        [[nodiscard]] constexpr session_key_t const &tx() noexcept;
        [[nodiscard]] constexpr session_key_t const &rx() noexcept;

    private:
        session_key_t receive_key;
        session_key_t transmit_key;

        std::size_t tx_counter{0};
        std::size_t rx_counter{0};
    };
    constexpr session_key_t const &secure_session::tx() noexcept {
        ++tx_counter;
        return transmit_key;
    }
    constexpr session_key_t const &secure_session::rx() noexcept {
        ++rx_counter;
        return receive_key;
    }

} // crypto

#endif //SECURE_SESSION_H
