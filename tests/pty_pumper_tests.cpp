//
// Created by inquaterni on 1/29/26.
//
#include <gtest/gtest.h>

#include "gmock/gmock-function-mocker.h"
#include "gmock/gmock-nice-strict.h"
#include "pty_pumper.h"

class fake_host : public net::host {
public:
    using host::host_type;
    fake_host(fake_host &&other) noexcept
    : host(std::forward<host_type>(other.m_host), other.m_ctx) {}
    fake_host(host_type &&type, asio::io_context &io_context) noexcept
    : host(std::move(type), io_context) {}

    MOCK_METHOD(bool, send, (ENetPeer *, const std::vector<net::u8> &data, net::u8, net::u32, bool), (const noexcept));
};
class fake_encryption final: public crypto::encryption {
public:
    [[nodiscard]] constexpr std::expected<std::vector<crypto::u8>, std::string>
    encrypt(const std::span<const crypto::u8> &data) override {
        return std::vector<crypto::u8>{data.begin(), data.end()};
    }
    [[nodiscard]] constexpr std::expected<std::vector<crypto::u8>, std::string>
    encrypt(const std::vector<crypto::u8> &data) override {
        return std::vector<crypto::u8>{data.begin(), data.end()};
    }
    [[nodiscard]] constexpr std::expected<std::vector<crypto::u8>, std::string>
    decrypt(const std::span<const crypto::u8> &ciphertext) override {
        return std::vector<crypto::u8>{ciphertext.begin(), ciphertext.end()};
    }
    [[nodiscard]] constexpr std::expected<std::vector<crypto::u8>, std::string>
    decrypt(const std::vector<crypto::u8> &ciphertext) override {
        return std::vector<crypto::u8>{ciphertext.begin(), ciphertext.end()};
    }
};
class fake_cipher final : public crypto::cipher {
public:
    explicit fake_cipher(std::unique_ptr<crypto::encryption> &&encryption) : cipher(std::move(encryption)) {}

    fake_cipher(fake_cipher &&other) noexcept
    : cipher(std::forward<std::unique_ptr<crypto::encryption>>(other.encryptor)) {};

    [[nodiscard]]
    std::expected<std::vector<net::u8>, std::string> encrypt(const std::span<const net::u8> data) const noexcept {
        return encryptor->encrypt(data);
    }
};
class pty_pumper_tests : public testing::Test {
public:
    pty_pumper_tests() noexcept : ctx(asio::io_context{}), mock_host(fake_host::host_type{nullptr, net::host_deleter{}}, ctx),
    mock_cipher(std::make_unique<fake_encryption>()) {}

    pty_pumper_tests(testing::StrictMock<fake_host> mock_host,
                     fake_cipher &&mock_cipher, ENetPeer *dummy_peer) noexcept :
        ctx(asio::io_context {}), mock_host(std::move(mock_host)), mock_cipher(std::forward<fake_cipher>(mock_cipher)), dummy_peer(dummy_peer) {}
    void SetUp() override {
        Test::SetUp();
        ASSERT_EQ(pipe(fds), 0);
        pumper = std::make_shared<net::pty_pumper>(
            ctx,
            fds[0],
            &mock_host,
            dummy_peer,
            mock_cipher
        );
    }
    void TearDown() override {
        Test::TearDown();
        close(fds[0]);
        close(fds[1]);
    }

protected:
    asio::io_context ctx;
    int fds[2] {};

    testing::StrictMock<fake_host> mock_host;
    fake_cipher mock_cipher;
    ENetPeer* dummy_peer = reinterpret_cast<ENetPeer *>(0xDEADBEEF);
    std::shared_ptr<net::pty_pumper> pumper;
};

TEST_F(pty_pumper_tests, reads_from_fd_and_sends) {
    pumper->start();
    EXPECT_CALL(mock_host, send(dummy_peer, testing::_, testing::_, testing::_, true))
    .WillOnce(testing::WithArgs<0, 1>(
        testing::Invoke([](ENetPeer*, const std::vector<net::u8>& data) -> bool {
            EXPECT_FALSE(data.empty());
            return true;
        })
    ));

    const std::vector<net::u8> payload{'h', 'e', 'l', 'l', 'o'};
    const auto written = write(fds[1], payload.data(), payload.size());
    ASSERT_EQ(static_cast<ssize_t>(payload.size()), written);

    ctx.restart();
    ctx.run_one();
    pumper->stop();
    ctx.stop();
}
TEST_F(pty_pumper_tests, stop_cancels_pending_ops) {
    using namespace std::chrono_literals;
    pumper->start();

    const std::vector<net::u8> payload{'h', 'e', 'l', 'l', 'o'};
    auto written = write(fds[1], payload.data(), payload.size());
    ASSERT_EQ(static_cast<ssize_t>(payload.size()), written);
    auto called = false;
    EXPECT_CALL(mock_host, send(dummy_peer, testing::_, testing::_, testing::_, true)).WillOnce(
        testing::WithArgs<0, 1>(
            testing::Invoke([&](ENetPeer*, const std::vector<net::u8> &data) -> bool {
                EXPECT_FALSE(data.empty());
                called = true;
                return true;
            })
        ));

    ctx.restart();
    ctx.run_one();
    ctx.stop();
    pumper->stop();
    EXPECT_TRUE(called);

    const std::vector<net::u8> payload3{'o', 'k', 'a', 'y'};
    written = write(fds[1], payload3.data(), payload3.size());
    ASSERT_EQ(static_cast<ssize_t>(payload3.size()), written);

    EXPECT_CALL(mock_host, send(testing::_, testing::_, testing::_, testing::_, testing::_)).Times(0);
    ctx.restart();
    ctx.run_one();
    ctx.stop();
}
TEST_F(pty_pumper_tests, handles_pipe_closure_gracefully) {
    pumper->start();
    close(fds[1]);
    ctx.run_one();
    EXPECT_NO_THROW();
}
TEST_F(pty_pumper_tests, large_buffer) {
    using namespace std::chrono_literals;
    pumper->start();
    const auto payload = std::vector<net::u8>(50000, '@');
    EXPECT_CALL(mock_host, send(testing::_, testing::_, testing::_, testing::_, testing::_)).Times(testing::AtLeast(13));
    write(fds[1], payload.data(), payload.size());
    ctx.run_for(50ms);
    EXPECT_NO_THROW();
}
