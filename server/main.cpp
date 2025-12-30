//
// Created by inquaterni on 12/30/25.
//
#include "context.h"
#include "server.h"
#include "spdlog/spdlog.h"

int main() {
    // 🚨🚨🚨 SINGLETON DETECTED 🚨🚨🚨
    enet::context::get_instance();
    [[maybe_unused]]
    auto server = enet::server::create(ENET_HOST_ANY, 6969);
    if (!server) {
        spdlog::critical("Failed to create server: {}", server.error());
        return EXIT_FAILURE;
    }

    spdlog::info("Server is initialized");

    return EXIT_SUCCESS;
}
