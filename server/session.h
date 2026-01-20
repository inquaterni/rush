//
// Created by inquaterni on 1/18/26.
//

#ifndef SESSION_H
#define SESSION_H
#include <expected>
#include <fcntl.h>
#include <pty.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "types.h"
namespace pty {

class session {
public:
    session() = delete;
    session(const session&) = delete;
    session& operator=(const session&) = delete;

    constexpr session(session&& other) noexcept
    : master_fd(std::exchange(other.master_fd, -1)),
      child_pid(std::exchange(other.child_pid, -1)) {}
    constexpr session& operator=(session&& other) noexcept {
        if (this != &other) {
            cleanup();
            master_fd = std::exchange(other.master_fd, -1);
            child_pid = std::exchange(other.child_pid, -1);
        }
        return *this;
    }

    [[nodiscard]]
    constexpr int fd() const noexcept { return master_fd; }
    [[nodiscard]]
    constexpr pid_t pid() const noexcept { return child_pid; }

    [[nodiscard]]
    constexpr bool write(const std::string_view data) const noexcept {
        return ::write(master_fd, data.data(), data.size()) != -1;
    };
    [[nodiscard]]
    constexpr bool write(const std::vector<net::u8> &data) const noexcept {
        return ::write(master_fd, data.data(), data.size()) != -1;
    };

    static constexpr std::expected<session, std::string> create(const std::string_view shell) noexcept {
        const int master = posix_openpt(O_RDWR | O_NOCTTY);
        if (master == -1) {
            return std::unexpected{ "Failed to open master pty" };
        }

        if (grantpt(master) == -1 || unlockpt(master) == -1) {
            close(master);
            return std::unexpected{ "Failed to grant/unlock pty" };
        }

        const char* slave_name = ptsname(master);
        if (!slave_name) {
            close(master);
            return std::unexpected{ "Failed to obtain slave name" };
        }

        const pid_t child = fork();

        if (child == -1) {
            close(master);
            return std::unexpected{ "Failed to fork process" };
        }

        if (child == 0) {
            close(master);
            setsid();

            const int slave_fd = open(slave_name, O_RDWR);
            if (slave_fd == -1) {
                std::exit(1);
            }

            ioctl(slave_fd, TIOCSCTTY, 0);

            termios term{};
            if (tcgetattr(slave_fd, &term) == 0) {
                cfmakeraw(&term);
                term.c_iflag |= ICRNL | IUTF8;
                term.c_oflag |= OPOST | ONLCR;
                term.c_lflag |= ECHO | ICANON | ISIG | IEXTEN;

                winsize ws{ .ws_row = 24, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0 };
                ioctl(slave_fd, TIOCSWINSZ, &ws);
                tcsetattr(slave_fd, TCSANOW, &term);
            }

            dup2(slave_fd, STDIN_FILENO);
            dup2(slave_fd, STDOUT_FILENO);
            dup2(slave_fd, STDERR_FILENO);

            if (slave_fd > STDERR_FILENO) close(slave_fd);

            const char* env[] = { "TERM=xterm-256color", nullptr };
            execle(shell.data(), "-l", nullptr, env);

            std::exit(1);
        }

        return session{master, child};
    }

    static constexpr std::expected<std::unique_ptr<session>, std::string> create_unique(const std::string_view shell) noexcept {
        const int master = posix_openpt(O_RDWR | O_NOCTTY);
        if (master == -1) {
            return std::unexpected{ "Failed to open master pty" };
        }

        if (grantpt(master) == -1 || unlockpt(master) == -1) {
            close(master);
            return std::unexpected{ "Failed to grant/unlock pty" };
        }

        const char* slave_name = ptsname(master);
        if (!slave_name) {
            close(master);
            return std::unexpected{ "Failed to obtain slave name" };
        }

        const pid_t child = fork();

        if (child == -1) {
            close(master);
            return std::unexpected{ "Failed to fork process" };
        }

        if (child == 0) {
            close(master);
            setsid();

            const int slave_fd = open(slave_name, O_RDWR);
            if (slave_fd == -1) {
                std::exit(1);
            }

            ioctl(slave_fd, TIOCSCTTY, 0);

            termios term{};
            if (tcgetattr(slave_fd, &term) == 0) {
                cfmakeraw(&term);
                term.c_iflag |= ICRNL | IUTF8;
                term.c_oflag |= OPOST | ONLCR;
                term.c_lflag |= ECHO | ICANON | ISIG | IEXTEN;

                winsize ws{ .ws_row = 24, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0 };
                ioctl(slave_fd, TIOCSWINSZ, &ws);
                tcsetattr(slave_fd, TCSANOW, &term);
            }

            dup2(slave_fd, STDIN_FILENO);
            dup2(slave_fd, STDOUT_FILENO);
            dup2(slave_fd, STDERR_FILENO);

            if (slave_fd > STDERR_FILENO) close(slave_fd);

            const char* env[] = { "TERM=xterm-256color", nullptr };
            execle(shell.data(), "-l", nullptr, env);

            std::exit(1);
        }

        return std::unique_ptr<session> (new session{master, child});
    }

private:
    int master_fd {-1};
    pid_t child_pid {-1};

    constexpr session(const int master, const pid_t child) noexcept : master_fd{master}, child_pid{child} {}
    constexpr void cleanup() {
        if (master_fd != -1) {
            close(master_fd);
            master_fd = -1;
        }
        if (child_pid > 0) {
            waitpid(child_pid, nullptr, 0);
            child_pid = -1;
        }
    }
};

} // pty

#endif //SESSION_H
