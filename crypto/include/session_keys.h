//
// Created by inquaterni on 1/7/26.
//

#ifndef SECURE_SESSION_H
#define SECURE_SESSION_H
#include "types.h"

namespace crypto {

    class session_keys {
    public:
        session_keys(const session_key_t & /* rx */, const session_key_t & /* tx */) noexcept;
        session_keys(session_key_t && /* rx */, session_key_t && /* tx */) noexcept;

        session_keys(const u8 * /* rx */, const u8 * /* tx */) noexcept;

        [[nodiscard]] constexpr session_key_t const &tx() const noexcept { return transmit_key; }
        [[nodiscard]] constexpr session_key_t const &rx() const noexcept { return receive_key; }

    private:
        session_key_t receive_key;
        session_key_t transmit_key;
    };

} // crypto

#endif //SECURE_SESSION_H
