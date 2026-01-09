//
// Created by inquaterni on 12/31/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include <expected>
#include <memory>
#include <thread>
#include <utility>

#include "../net/include/host_deleter.h"
#include "../net/include/peer_deleter.h"
#include "packet.h"
#include "packet_serializer.h"

namespace net {
    template<typename T>
    class queue {
        constexpr static int min_capacity = 8;
        T* m_ring_buffer;
        int m_front;
        int m_rear;
        int m_capacity;

    public:
        using value_type = T;
        using reference = T&;

        constexpr queue() noexcept: queue(min_capacity){}

        explicit constexpr queue(const int capacity) noexcept
            : m_ring_buffer{ nullptr }
            , m_front{ 0 }
            , m_rear{ 0 }
            , m_capacity{ 0 }
        {
            m_ring_buffer = static_cast<T*>(operator new(capacity * sizeof(T)));
            m_capacity = capacity;
        }

        ~queue() {
            clear();
            operator delete(m_ring_buffer);
        }

        constexpr queue(const queue& other) noexcept
            : queue(other.m_capacity) {}

        friend constexpr void swap(queue& lhs, queue& rhs) noexcept {
            std::swap(lhs.m_ring_buffer, rhs.m_ring_buffer);
            std::swap(lhs.m_front, rhs.m_front);
            std::swap(lhs.m_rear, rhs.m_rear);
            std::swap(lhs.m_capacity, rhs.m_capacity);
        }

        constexpr queue& operator=(const queue& other) noexcept {
            if (this != &other) {
                queue temp{ other };
                swap(*this, temp);
            }
            return *this;
        }

        constexpr queue(queue&& other) noexcept : m_ring_buffer{ std::exchange(other.m_ring_buffer, nullptr) }
            , m_front{ other.m_front }
            , m_rear{ other.m_rear }
            , m_capacity{ other.m_capacity } {}

        constexpr queue& operator=(queue&& other) noexcept {
            queue temp{ std::move(other) };
            std::swap(*this, temp);
            return (*this);
        }

        [[nodiscard]] constexpr bool empty() const noexcept {
            return (m_rear == m_front);
        }

        [[nodiscard]] constexpr bool full() const noexcept {
            return (m_rear == m_front + m_capacity);
        }

        [[nodiscard]]
        constexpr int size() const noexcept {
            return (m_rear - m_front);
        }

        [[nodiscard]]
        constexpr int capacity() const noexcept {
            return m_capacity;
        }
        constexpr void resize() noexcept
        {
            T* new_array = static_cast<T*>(operator new(2 * m_capacity * sizeof(T)));

            const int new_size = size();
            for (int i{ 0 };i < new_size;++i) {
                new (&new_array[i]) T(std::move(m_ring_buffer[(i + m_front) % m_capacity]));
            }
            clear();
            operator delete(m_ring_buffer);

            m_ring_buffer = new_array;
            m_front = 0;
            m_rear = new_size;
            m_capacity *= 2;
        }

        constexpr void push(const T& value) noexcept {
            if (full())
                resize();
            new (&m_ring_buffer[(m_rear % m_capacity)]) T(value);
            m_rear++;
        }

        constexpr void push(T&& value) noexcept {
            if (full())
                resize();
            new(&m_ring_buffer[(m_rear % m_capacity)]) T(std::move(value));
            m_rear++;
        }

        constexpr void pop() noexcept {
            m_ring_buffer[m_front % m_capacity].~T();
            m_front++;
        }

        constexpr T& operator[](const int i) noexcept {
            return m_ring_buffer[(m_front + i) % m_capacity];
        }

        constexpr T& operator[](const int i) const noexcept {
            return m_ring_buffer[(m_front + i) % m_capacity];
        }

        constexpr T& front() noexcept {
            return m_ring_buffer[m_front % m_capacity];
        }

        constexpr T& back() noexcept {
            return m_ring_buffer[(m_rear - 1) % m_capacity];
        }

    private:
        constexpr void clear() noexcept {
            for (int i{ 0 }; i < size(); ++i) {
                m_ring_buffer[(m_front + i) % m_capacity].~T();
            }
        }
    };

    class client {
    public:
        using host = std::unique_ptr<ENetHost, host_deleter>;
        using peer = std::unique_ptr<ENetPeer, peer_deleter>;
        client() = delete;

        [[nodiscard]]
        static std::expected<client, std::string> create() noexcept;

        bool connect(std::string_view /* address */, int /* port */, short timeout = 5000) noexcept;
        template<class Tp>
        bool send(const Tp &pack, u8 channel_id = 0,
                  u32 flags = ENET_PACKET_FLAG_NO_ALLOCATE | ENET_PACKET_FLAG_RELIABLE) noexcept;
        constexpr void service(int timeout = 1000);
        template<typename Tp>
        std::expected<Tp, std::string> recv();

    private:
        host host_;
        peer server;
        queue<ENetEvent> events;
        std::jthread service_;

        explicit client(host && /* client host */) noexcept;
    };
    template<typename Tp>
    bool client::send(const Tp &pack, const u8 channel_id, const u32 flags) noexcept {
        const auto bytes = serial::packet_serializer::serialize(pack);
        if (!bytes) {
            return false;
        }
        const auto packet = enet_packet_create(bytes->asBytes().begin(), bytes->size() * sizeof(capnp::word), flags);

        if (!packet) {
            return false;
        }
        enet_peer_send(server.get(), channel_id, packet);
        enet_host_flush(host_.get());
        return true;
    }
    template<typename Tp>
    std::expected<Tp, std::string> client::recv() {
        for (int i {0}; i < events.size(); ++i) {
            if (const auto event = events[i]; event.packet) {
                const auto word_ptr = reinterpret_cast<const capnp::word *>(event.packet->data);
                const std::size_t word_size = event.packet->dataLength / sizeof(capnp::word);
                return serial::packet_serializer::deserialize<Tp>(std::span {word_ptr, word_size});
            }
        }
        return std::unexpected { "No corresponding event found." };
    }

    constexpr void client::service(const int timeout) {
        service_ = std::jthread {[&] {
            ENetEvent event;
            while (enet_host_service(host_.get(), &event, timeout) > 0) {
                switch (event.type) {
                    case ENET_EVENT_TYPE_RECEIVE: {
                        events.push(event);
                    } break;
                    default: break;
                }
            }
        }};

        service_.detach();
    }
} // net



#endif //CLIENT_H
