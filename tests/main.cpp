//
// Created by inquaterni on 1/14/26.
//

#include <gtest/gtest.h>
#include <sys/ioctl.h>

#include "packet_serializer.h"
#include "session.h"

TEST(packet_serializer_tests, handshake_round_trip) {
    crypto::pkey_t key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<crypto::u8>(i);
    }

    const net::packet original = net::handshake_packet{key};
    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::handshake_packet>(*result));

    const auto &decoded = std::get<net::handshake_packet>(*result);
    EXPECT_EQ(decoded.public_key, key);
}
TEST(packet_serializer_tests, shell_bytes_round_trip) {
    const std::vector<net::u8> data{1, 2, 3, 4, 5};
    const net::packet original = net::shell_message{net::packet_type::BYTES, data};

    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::shell_message>(*result));

    const auto &decoded = std::get<net::shell_message>(*result);
    EXPECT_EQ(decoded.type, net::packet_type::BYTES);
    EXPECT_EQ(decoded.bytes, data);
}
TEST(packet_serializer_tests, shell_disconnect_round_trip) {
    const std::vector<net::u8> data{9, 8, 7};
    const net::packet original = net::shell_message{net::packet_type::DISCONNECT, data};

    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::shell_message>(*result));

    const auto &decoded = std::get<net::shell_message>(*result);
    EXPECT_EQ(decoded.type, net::packet_type::DISCONNECT);
    EXPECT_EQ(decoded.bytes, data);
}
TEST(packet_serializer_tests, shell_signal_round_trip) {
    const std::string msg = "TERM";
    const std::vector<net::u8> data{msg.begin(), msg.end()};
    const net::packet original = net::shell_message{net::packet_type::SIGNAL, data};

    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::shell_message>(*result));

    const auto &decoded = std::get<net::shell_message>(*result);
    EXPECT_EQ(decoded.type, net::packet_type::SIGNAL);
    EXPECT_EQ(decoded.bytes, data);
}
TEST(packet_serializer_tests, auth_request_round_trip) {
    const std::string username = "user";
    const std::string password = "password";
    const net::packet original = net::auth_packet{username, password};

    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::auth_packet>(*result));

    const auto &decoded = std::get<net::auth_packet>(*result);
    EXPECT_EQ(decoded.username, username);
    EXPECT_EQ(decoded.password, password);
}
TEST(packet_serializer_tests, auth_response_round_trip) {
    const std::string response = "OK";
    const std::vector<net::u8> data{response.begin(), response.end()};
    const net::packet original = net::shell_message{net::packet_type::AUTH_RESPONSE, data};

    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::shell_message>(*result));

    const auto &decoded = std::get<net::shell_message>(*result);
    EXPECT_EQ(decoded.type, net::packet_type::AUTH_RESPONSE);
    EXPECT_EQ(decoded.bytes, data);
}
TEST(packet_serializer_tests, resize_round_trip) {
    winsize ws{};
    ws.ws_row = 24;
    ws.ws_col = 80;
    ws.ws_xpixel = 640;
    ws.ws_ypixel = 480;

    const net::packet original = net::resize_packet{ws};

    const auto words = serial::packet_serializer::serialize(original);
    const std::span span{words.begin(), words.size()};

    const auto result = serial::packet_serializer::deserialize(span);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<net::resize_packet>(*result));

    const auto &decoded = std::get<net::resize_packet>(*result);
    EXPECT_EQ(decoded.ws.ws_row, ws.ws_row);
    EXPECT_EQ(decoded.ws.ws_col, ws.ws_col);
    EXPECT_EQ(decoded.ws.ws_xpixel, ws.ws_xpixel);
    EXPECT_EQ(decoded.ws.ws_ypixel, ws.ws_ypixel);
}


TEST(term_session_tests, pam_conversation_populates_responses) {
    using pty::session;
    const std::string password = "secret";
    std::string_view pwd_view = password;

    pam_message msg1{};
    msg1.msg_style = PAM_PROMPT_ECHO_OFF;
    msg1.msg = const_cast<char *>("Password:");

    pam_message msg2{};
    msg2.msg_style = PAM_ERROR_MSG;
    msg2.msg = const_cast<char *>("Error:");

    const pam_message *msgs[2] = {&msg1, &msg2};
    pam_response *resp = nullptr;

    const int rc = session::pam_conversation(2, msgs, &resp, &pwd_view);
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_NE(resp, nullptr);
    ASSERT_NE(resp[0].resp, nullptr);
    EXPECT_STREQ(resp[0].resp, password.c_str());
    EXPECT_EQ(resp[0].resp_retcode, 0);
    EXPECT_EQ(resp[1].resp, nullptr);
    EXPECT_EQ(resp[1].resp_retcode, 0);
    free(resp[0].resp);
    free(resp[1].resp);
    free(resp);
}
TEST(term_session_tests, pam_conversation_null_appdata_returns_error) {
    using pty::session;

    pam_message msg{};
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = const_cast<char *>("Password:");

    const pam_message *msgs[1] = {&msg};
    pam_response *resp = nullptr;

    const int rc = session::pam_conversation(1, msgs, &resp, nullptr);
    EXPECT_EQ(rc, PAM_BAD_ITEM);
    EXPECT_EQ(resp, nullptr);
}