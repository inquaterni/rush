//
// Created by inquaterni on 12/30/25.
//

#ifndef SERVER_H
#define SERVER_H
#include <expected>
#include <memory>
#include "host_deleter.h"

namespace enet {
    class server final {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        static constexpr short max_clients = 32;

        server() = delete;
        ~server() = default;

        server(server && /* other */) noexcept;
        server &operator=(server && /* other */) noexcept;

        server(const server & /* other */) = delete;
        server &operator=(const server & /* other */) = delete;

        [[nodiscard]]
        static std::expected<server, std::string> create(in6_addr /* address */, int /* port */);

    private:
        host host_;

        explicit server(host && /* server host */) noexcept;
    };
} // namespace enet


#endif // SERVER_H
