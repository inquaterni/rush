//
// Created by inquaterni on 12/30/25.
//

#include "../include/context.h"

#define ENET_IMPLEMENTATION
#include "enet.h"

namespace enet {
    context::~context() { enet_deinitialize(); }
    context &context::get_instance() noexcept {
        static context instance;
        return instance;
    }
    bool context::is_initialized() noexcept { return initialized; }
    context::context() {
        // ReSharper disable once CppDFAConstantConditions
        initialized = enet_initialize() == 0;
    }
} // namespace enet

