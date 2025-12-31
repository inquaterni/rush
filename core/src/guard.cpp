//
// Created by inquaterni on 12/30/25.
//

#include "../include/guard.h"

#define ENET_IMPLEMENTATION
#include "enet.h"
#include "sodium.h"

namespace enet {
    guard::~guard() { enet_deinitialize(); }
    guard &guard::get_instance() noexcept {
        static guard instance {};
        return instance;
    }
    bool guard::is_initialized() noexcept { return initialized; }
    guard::guard() {
        // ReSharper disable once CppDFAConstantConditions
        initialized = enet_initialize() == 0;
    }
} // namespace enet

namespace sodium {
    guard &guard::get_instance() noexcept {
        static guard instance{};
        return instance;
    }
    bool guard::is_initialized() noexcept { return initialized; }
    guard::guard() {
        initialized = sodium_init() == 0;
    }
} // namespace sodium
