//
// Created by inquaterni on 1/19/26.
//

#ifndef SIGNAL_H
#define SIGNAL_H
#include <algorithm>
#include <array>
#include <optional>
#include <string_view>

#if defined(__linux__)
#include <csignal>
#endif

namespace net {
    struct sig_pair {
        int os_signal;
        std::string_view rfc_name;
    };
#if defined(__linux__)
    constexpr auto signal_table = std::to_array<sig_pair>({
        { SIGHUP,  "HUP"  },
        { SIGINT,  "INT"  },
        { SIGQUIT, "QUIT" },
        { SIGTERM, "TERM" },
        { SIGUSR1, "USR1" },
        { SIGUSR2, "USR2" }
    });
#endif

    constexpr std::optional<std::string_view> sig2name(int sig) {
        const auto it = std::ranges::find_if(signal_table,
            [sig](const sig_pair& pair) {
                return pair.os_signal == sig;
        });
        if (it == signal_table.end()) return std::nullopt;

        return it->rfc_name;
    }

    constexpr std::optional<int> name2sig(std::string_view name) {
        const auto it = std::ranges::find_if(signal_table,
            [name](const sig_pair& pair) {
            return pair.rfc_name == name;
        });
        if (it == signal_table.end()) return std::nullopt;

        return it->os_signal;
    }
} // net

#endif //SIGNAL_H
