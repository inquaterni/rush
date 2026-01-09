//
// Created by inquaterni on 1/1/26.
//

#ifndef TYPES_H
#define TYPES_H
#include <array>
#include <memory>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_kx.h>
#include "packet_deleter.h"

namespace net {
    using u8 = unsigned char;
    using u32 = unsigned;
    using packet_ptr = std::unique_ptr<ENetPacket, packet_deleter>;
} // net

#endif //TYPES_H
