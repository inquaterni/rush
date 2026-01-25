//
// Created by inquaterni on 1/18/26.
//

#ifndef SESSION_H
#define SESSION_H
#include <expected>
#include <fcntl.h>
#include <pty.h>
#include <pwd.h>
#include <grp.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <security/pam_appl.h>

#include "spdlog/spdlog.h"
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

    static constexpr std::expected<std::unique_ptr<session>, std::string> create_unique(const std::string_view username, const std::string_view pwd) noexcept {
        errno = 0;

        if (!pam_pwd_check(username, pwd)) {
            return std::unexpected {"Failed to authenticate user '" + std::string(username) + "'."};
        }

        const passwd *pw = getpwnam(username.data());
        if (!pw) {
            return std::unexpected{"User not found: " + std::string{username}};
        }

        [[maybe_unused]] uid_t target_uid = pw->pw_uid;
        const gid_t target_gid = pw->pw_gid;
        const std::string dest_shell = pw->pw_shell ? pw->pw_shell : "/bin/sh";
        const std::string dest_home = pw->pw_dir ? pw->pw_dir : "/";
        const std::string dest_user  = pw->pw_name;

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

        const pid_t slave = fork();

        if (slave == -1) {
            close(master);
            return std::unexpected{ "Failed to fork process" };
        }

        if (slave == 0) {
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

            if (initgroups(dest_user.c_str(), target_gid) < 0) {
                spdlog::critical("Failed to initialize groups: {}", strerror(errno));
                std::exit(1);
            }
            if (setgid(target_gid) < 0) {
                spdlog::critical("Failed to set group id for slave process: {}", strerror(errno));
                std::exit(1);
            }
            if (setuid(target_uid) < 0) {
                spdlog::critical("Failed to set user id: {}", strerror(errno));
                std::exit(1);
            }
            if (chdir(dest_home.c_str()) < 0) {
                spdlog::critical("Failed to change directory to {} due to: {}", dest_home, strerror(errno));
                std::exit(1);
            }

            std::string env_term = "TERM=xterm-256color";
            std::string env_home = "HOME=" + dest_home;
            std::string env_user = "USER=" + dest_user;
            std::string env_shell = "SHELL=" + dest_shell;
            std::string env_path = "PATH=/usr/local/bin:/usr/bin:/bin";
            char *const envp[] = {env_term.data(),  env_home.data(), env_user.data(),
                                   env_shell.data(), env_path.data(), nullptr};

            std::string shell_name = dest_shell.substr(dest_shell.find_last_of('/') + 1);
            std::string argv0 = "-" + shell_name;
            char *const argv[] = {
                    argv0.data(),
                    nullptr,
            };

            execve(dest_shell.c_str(), argv, envp);

            std::exit(1);
        }

        return std::unique_ptr<session> (new session{master, slave});
    }

    static constexpr int pam_conversation(const int num_msg, const pam_message ** msg, pam_response ** resp, void* appdata_ptr) {
        const auto *password = static_cast<std::string_view*>(appdata_ptr);
        if (!password) return PAM_BAD_ITEM;

        *resp = static_cast<pam_response *>(calloc(num_msg, sizeof(pam_response)));
        if (!*resp) return PAM_BUF_ERR;

        for (int i = 0; i < num_msg; ++i) {
            if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
                (*resp)[i].resp = strdup(password->data());
                (*resp)[i].resp_retcode = 0;
            }
            else {
                (*resp)[i].resp = nullptr;
                (*resp)[i].resp_retcode = 0;
            }
        }
        return PAM_SUCCESS;
    }
    static constexpr bool pam_pwd_check(const std::string_view username, std::string_view pwd) noexcept {
        const pam_conv conv {
            pam_conversation,
            &pwd
        };

        pam_handle_t *pamh = nullptr;
        int retval = pam_start("login", username.data(), &conv, &pamh);
        if (retval != PAM_SUCCESS) return false;

        retval = pam_authenticate(pamh, 0);
        if (retval != PAM_SUCCESS) {
            pam_end(pamh, retval);
            return false;
        };

        retval = pam_acct_mgmt(pamh, 0);
        bool success = retval == PAM_SUCCESS;
        pam_end(pamh, retval);

        return success;
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
