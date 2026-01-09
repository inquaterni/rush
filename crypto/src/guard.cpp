//
// Created by inquaterni on 1/7/26.
//

#include "../include/guard.h"

#include <sodium/core.h>

namespace crypto {
    guard &guard::get_instance() noexcept {
        static guard instance{};
        return instance;
    }
    bool guard::is_initialized() noexcept { return initialized; }
    guard::guard() {
        initialized = sodium_init() == 0;
    }
} // crypto