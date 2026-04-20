//
// Created by inquaterni on 1/18/26.
//

#ifndef GUARD_H
#define GUARD_H

#include <expected>
#include <iostream>
#include <poll.h>
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
        [[nodiscard]]
        constexpr bool is_raw() const noexcept {return raw;}

        constexpr bool begin_pwd(std::string_view prompt) noexcept;
        constexpr std::optional<std::string> poll_pwd() noexcept;
        constexpr void end_pwd() noexcept;
        [[nodiscard]] constexpr bool pwd_active() const noexcept { return m_pwd_active; }

        constexpr guard(const guard &other) = delete;
        constexpr guard &operator=(const guard &other) = delete;
        constexpr guard(guard &&other) = delete;
        constexpr guard &operator=(guard &&other) = delete;

    private:
        static constinit inline bool initialized{false};
        bool raw{false};
        termios orig_term{};

        bool m_pwd_active {false};
        termios m_pwd_old {};
        std::string m_pwd_buf;

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
        auto _ = write(STDOUT_FILENO, "\n\r", 2);
        tcflush(STDIN_FILENO, TCIFLUSH);
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
    constexpr bool guard::begin_pwd(const std::string_view prompt) noexcept {
        if (m_pwd_active) return false;
        if (tcgetattr(STDIN_FILENO, &m_pwd_old) < 0) return false;

        termios no_echo = m_pwd_old;
        no_echo.c_lflag &= ~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &no_echo) < 0) return false;

        auto _ = write(STDOUT_FILENO, prompt.data(), prompt.size());
        m_pwd_buf.clear();
        m_pwd_active = true;
        return true;
    }
    constexpr std::optional<std::string> guard::poll_pwd() noexcept {
        if (!m_pwd_active) return std::nullopt;

        pollfd pfd {STDIN_FILENO, POLLIN, 0};
        while (poll(&pfd, 1, 0) > 0) {
            char c;
            if (read(STDIN_FILENO, &c, 1) <= 0) break;

            if (c == '\n' || c == '\r') {
                end_pwd();
                return std::move(m_pwd_buf);
            }
            if (c == 0x7F || c == '\b') {
                if (!m_pwd_buf.empty()) m_pwd_buf.pop_back();
            } else {
                m_pwd_buf += c;
            }
        }
        return std::nullopt;
    }
    constexpr void guard::end_pwd() noexcept {
        if (!m_pwd_active) return;
        tcsetattr(STDIN_FILENO, TCSANOW, &m_pwd_old);
        auto _ = write(STDOUT_FILENO, "\n\r", 1);
        m_pwd_active = false;
    }
} // term

#endif //GUARD_H