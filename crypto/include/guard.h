//
// Created by inquaterni on 1/7/26.
//

#ifndef CRYPTO_GUARD_H
#define CRYPTO_GUARD_H

namespace crypto {
    class guard {
    public:
        static guard &get_instance() noexcept;
        static bool is_initialized() noexcept;

        guard(const guard &other) = delete;
        guard &operator=(const guard &other) = delete;
        guard(guard &&other) = delete;
        guard &operator=(guard &&other) = delete;

    private:
        static constinit inline bool initialized{false};
        guard();
    };

} // crypto

#endif // CRYPTO_GUARD_H
