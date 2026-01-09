//
// Created by inquaterni on 12/30/25.
//

#include "../include/guard.h"

#define ENET_IMPLEMENTATION
#include "enet.h"

namespace net {
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
} // net
