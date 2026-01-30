# RUSH

Rush is a modern, high-performance C++23 networking project designed to demonstrate robust, secure, and clear network application architecture. It leverages the reliability of ENet's UDP multiplexing, the asynchronous power of Asio, and the security of XChaCha20-Poly1305.

> [!WARNING]
> **THIS SOFTWARE IS UNSAFE. DO NOT USE IN SENSITIVE ENVIRONMENTS.**
>
> The author is **NOT** a security engineer and has **NO** security-related experience. This project has **NEVER** been audited and most certainly contains **CRITICAL SECURITY VULNERABILITIES**.
>
> I **HIGHLY DISCOURAGE** any real-world usage of this software. It is provided exclusively for educational purposes. Use at your own risk.

> [!IMPORTANT]
> **A Plea to Security Engineers**
>
> Please, **test this software to its limits**! If you have the skills, I `beg` you to try to break the encryption, bypass authentication, or crash the server. This project is a candid attempt to learn, and I would value nothing more than your harshest feedback and vulnerability reports.
>
> *Please, do your worst.*

## Features

- **Multiplexed Reliable UDP**: Built on top of **ENet**, providing connection-oriented, reliable, and sequenced packet delivery over UDP with multiple channels.
- **Modern C++23 Architecture**: Written with the latest C++ standards in mind, utilizing `std::expected` for error handling, `std::span` for memory safety, and `constexpr` for compile-time optimizations.
- **Asynchronous I/O**: Fully integrated with **Asio** and C++20 coroutines (`asio::awaitable`, `co_await`) for specific, non-blocking event loops.
- **Strong Encryption**: Secure communication using **XChaCha20-Poly1305** authenticated encryption (via **libsodium**).
- **Zero-Copy Serialization**: High-performance binary serialization using **Cap'n Proto**.
- **Type-Safe Event Handling**: Clean, variant-based event dispatching system using `std::visit`.
- **Thread-Safe**: Designed for concurrency with `moodycamel::ConcurrentQueue` and thread-safe host management. (Yet, this queue is overkill, as locks are used anyway. ( ͡° ͜ʖ ͡°))

## Requirements

- C++23 compatible compiler (e.g., GCC 13+, Clang 16+)
- CMake 3.31+
- **Linux** (Windows is not supported, MacOS and other UNIX-like systems are untested)
- **PAM Development Headers**
- **sshd PAM usage** (Server expects to authenticate via PAM using `sshd` configuration)

## Dependencies

- [`Standalone Asio`] (https://github.com/chriskohlhoff/asio)
- [`ENet`] (https://github.com/zpl-c/enet)
- [`libsodium`] (https://github.com/jedisct1/libsodium)
- [`Cap'n Proto`] (https://github.com/capnproto/capnproto)
- [`fmt`] (https://github.com/fmtlib/fmt)
- [`spdlog`] (https://github.com/gabime/spdlog)
- [`zstd`] (https://github.com/facebook/zstd)
- [`moodycamel::ConcurrentQueue`] (https://github.com/cameron314/concurrentqueue)
- [`Linux-PAM`] (https://github.com/linux-pam/linux-pam)

## Building

Rush uses CMake as its build system. To build the project:

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

## Running

After building, you will have two main executables: `server` and `client`.

### Server

The server listens on port `6969` and handles incoming connections, authentication, requires elevated priveleges (for user logging in).

```bash
sudo ./server/server
```

### Client

The client connects to the server and demonstrates the secure, reliable communication channel.

```bash
./client/client <username>@<host>
```

## Structure

- `net/`: Core networking logic (Host, Peer, Packet wrappers).
- `crypto/`: Encryption primitives (Key management, XChaCha20-Poly1305).
- `serial/`: Serialization helpers (Cap'n Proto integration).
- `term/`: Terminal interface utilities.
- `pack/`: Compression utilities using zstd. Not used currently.
- `server/`: Server application implementation.
- `client/`: Client application implementation.

## License

This project is licensed under the **MIT License**.

This project relies on several third-party libraries (ENet, Asio, libsodium, Cap'n Proto, fmt, spdlog, zstd, ConcurrentQueue, Linux-PAM). Please refer to their official repositories or installed package documentation for license details.
