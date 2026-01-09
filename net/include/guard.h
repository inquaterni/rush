//
// Created by inquaterni on 12/30/25.
//

#ifndef ENET_GUARD_H
#define ENET_GUARD_H

namespace net {

    class guard {
    public:
        ~guard();

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
} // net
#endif // ENET_GUARD_H
