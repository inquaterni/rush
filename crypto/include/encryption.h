//
// Created by inquaterni on 1/11/26.
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

        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::span<const u8> & /* encrypted */) = 0;
        [[nodiscard]] virtual constexpr std::expected<std::vector<u8>, std::string> decrypt(const std::vector<u8> & /* encrypted */) = 0;
    };

} // crypto

#endif //ENCRYPTION_H
