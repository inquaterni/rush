//
// Created by inquaterni on 1/18/26.
//

#ifndef GUARD_H
#define GUARD_H

#include <expected>
#include <iostream>
#include <termios.h>
#include <unistd.h>

namespace term {

    class guard {
    public:
        constexpr ~guard();

        static constexpr guard &get_instance() noexcept;
        static constexpr bool is_initialized() noexcept;
        constexpr bool enable_raw_mode() noexcept;
        constexpr void disable_raw_mode() noexcept;
        constexpr bool is_raw() const noexcept {return raw;}

        constexpr guard(const guard &other) = delete;
        constexpr guard &operator=(const guard &other) = delete;
        constexpr guard(guard &&other) = delete;
        constexpr guard &operator=(guard &&other) = delete;

    private:
        static constinit inline bool initialized{false};
        bool raw{false};
        termios orig_term{};
        constexpr guard();
    };
    constexpr guard::~guard() {
        disable_raw_mode();
    }
    constexpr guard &guard::get_instance() noexcept {
        static guard instance{};
        return instance;
    }
    constexpr bool guard::is_initialized() noexcept { return initialized; }
    constexpr bool guard::enable_raw_mode() noexcept {
        if (raw) return true;

        termios raw_term = orig_term;
        cfmakeraw(&raw_term);
        raw = tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw_term) != -1;
        return raw;
    }
    constexpr void guard::disable_raw_mode() noexcept {
        if (!raw) return;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);
        raw = false;
    }
    constexpr guard::guard() { initialized = tcgetattr(STDIN_FILENO, &orig_term) != -1;
    }

    constexpr std::expected<std::string, std::string> getpwd(const std::string_view &prompt) {
        termios old {};
        if (tcgetattr(STDIN_FILENO, &old) < 0) {
            return std::unexpected {"Unable to get terminal settings."};
        }
        termios new_term = old;
        new_term.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) < 0) {
            return std::unexpected {"Unable to apply terminal settings."};
        }

        std::cout << prompt << std::flush;
        std::string password;
        std::getline(std::cin, password);

        if (tcsetattr(STDIN_FILENO, TCSANOW, &old) < 0) {
            return std::unexpected {"Unable to restore terminal settings."};
        }
        std::cout << "\n";

        return password;
    }
} // term

#endif //GUARD_H