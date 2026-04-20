//
// Created by inquaterni on 3/30/26.
//

#ifndef OBJECT_POOL_H
#define OBJECT_POOL_H
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

#include "types.h"

namespace net {

#if defined(__x86_64__) || defined(_M_X64)
    // Tagged pointer structure:
    // Bits:
    //  63      48 47                    0
    // ┌────────┬────────────────────────┐
    // │  tag   │       pointer          │
    // └────────┴────────────────────────┘
    template<typename T>
    struct tagged_ptr {
        using pointer = T*;
        static constexpr std::size_t pointer_mask = 0x0000'FFFF'FFFF'FFFF;
        static constexpr u8 tag_shift = 48;

        static tagged_ptr make(T* ptr, const u16 tag = 0) noexcept{
            return tagged_ptr {
                static_cast<std::uintptr_t>(tag) << tag_shift | (reinterpret_cast<std::uintptr_t>(ptr) & pointer_mask)
            };
        }
        pointer ptr() const noexcept {
            return reinterpret_cast<pointer>(value & pointer_mask);
        }
        [[nodiscard]]
        u16 tag() const noexcept {
            return value >> tag_shift;
        }
        tagged_ptr bumped() const noexcept {
            return make(ptr(), tag() + 1);
        }

        explicit constexpr tagged_ptr(const std::uintptr_t ptr) noexcept: value {ptr} {}
        constexpr tagged_ptr() noexcept: value {reinterpret_cast<std::uintptr_t>(nullptr)} {}

    private:
        std::uintptr_t value;
    };

    template<typename T>
    class object_pool {
    public:
        using value_type = T;
        using pointer = T *;
        using pool_ptr = std::unique_ptr<value_type, void(*)(value_type*)>;

        static constexpr object_pool &get_instance() noexcept {
            static object_pool instance {};
            return instance;
        }

        template<typename... Args>
        constexpr pool_ptr acquire(Args&&... args) noexcept {
            pointer raw {nullptr};

            node_tptr old_head = free_list.load(std::memory_order_acquire);
            while (old_head.ptr()) {
                if (node_tptr new_head = node_tptr::make(old_head.ptr()->next, old_head.tag());
                    free_list.compare_exchange_weak(old_head, new_head, std::memory_order_acquire, std::memory_order_relaxed)) {
                    raw = new (old_head.ptr()->storage) value_type(std::forward<Args>(args)...);
                    return pool_ptr {raw, [](T *p) { get_instance().release(p); }};
                    }
            }

            std::size_t idx = current_chunk_index.fetch_add(1, std::memory_order_relaxed);

            {
                std::scoped_lock lock(m_mutex);
                if (idx >= m_pool.size() * m_chunk_capacity) {
                    m_pool.emplace_back(m_chunk_capacity);
                    current_chunk_index.store(1, std::memory_order_relaxed);
                    idx = 0;
                }
                node* block = &m_pool.back().blocks[idx];
                raw = new (block->storage) value_type(std::forward<Args>(args)...);
            }

            return pool_ptr {raw, [](T *p) noexcept {
                get_instance().release(p);
            }};
        }
        constexpr std::size_t capacity() noexcept {
            std::scoped_lock lock(m_mutex);
            return m_pool.size() * m_chunk_capacity;
        }

        constexpr object_pool(const object_pool &other) = delete;
        constexpr object_pool &operator=(const object_pool &other) = delete;
        constexpr object_pool(object_pool &&other) = delete;
        constexpr object_pool &operator=(object_pool &&other) = delete;

        constexpr void release(pointer p) {
            if (!p) return;
            p->~value_type();

            node* block = reinterpret_cast<node*>(p);

            node_tptr old_head = free_list.load(std::memory_order_relaxed);
            node_tptr new_head;
            do {
                block->next = old_head.ptr();
                new_head = node_tptr::make(block, old_head.tag() + 1);
            } while (!free_list.compare_exchange_weak(old_head, new_head, std::memory_order_release, std::memory_order_relaxed));
        }

    private:
        std::mutex m_mutex {};

        union node {
            node* next;
            alignas(value_type) char storage[sizeof(value_type)];
        };
        using node_tptr = tagged_ptr<node>;

        struct chunk {
            std::unique_ptr<node[]> blocks;
            constexpr explicit chunk(const std::size_t capacity) noexcept
            : blocks {new node[capacity]} {}
        };
        static_assert(std::atomic<node_tptr>::is_always_lock_free);

        std::vector<chunk> m_pool {};
        std::atomic<std::size_t> current_chunk_index {0};
        std::size_t m_chunk_capacity;
        std::atomic<node_tptr> free_list {node_tptr::make(nullptr)};

        explicit constexpr object_pool(std::size_t chunk_capacity = 4096) noexcept
        : m_chunk_capacity(chunk_capacity) {
            m_pool.emplace_back(chunk_capacity);
        }
    };

#elif defined(__aarch64__) || defined(__arm__) || defined(_M_ARM64) || defined(_M_ARM)

    template<typename T>
    class object_pool {
    public:
        using value_type = T;
        using pointer = T *;
        using pool_ptr = std::unique_ptr<value_type, void(*)(value_type*)>;

        static constexpr object_pool &get_instance() noexcept {
            static object_pool instance {};
            return instance;
        }

        template<typename... Args>
        constexpr pool_ptr acquire(Args&&... args) noexcept {
            pointer raw {nullptr};

            {
                std::scoped_lock lock(m_free_list_mutex);
                if (free_list) {
                    node* head = free_list;
                    free_list = head->next;
                    raw = new (head->storage) value_type(std::forward<Args>(args)...);
                    return pool_ptr {raw, [](T *p) { get_instance().release(p); }};
                }
            }

            std::size_t idx = current_chunk_index.fetch_add(1, std::memory_order_relaxed);

            {
                std::scoped_lock lock(m_mutex);
                if (idx >= m_pool.size() * m_chunk_capacity) {
                    m_pool.emplace_back(m_chunk_capacity);
                    current_chunk_index.store(1, std::memory_order_relaxed);
                    idx = 0;
                }
                node* block = &m_pool.back().blocks[idx];
                raw = new (block->storage) value_type(std::forward<Args>(args)...);
            }

            return pool_ptr {raw, [](T *p) noexcept {
                get_instance().release(p);
            }};
        }

        constexpr std::size_t capacity() noexcept {
            std::scoped_lock lock(m_mutex);
            return m_pool.size() * m_chunk_capacity;
        }

        constexpr object_pool(const object_pool &other) = delete;
        constexpr object_pool &operator=(const object_pool &other) = delete;
        constexpr object_pool(object_pool &&other) = delete;
        constexpr object_pool &operator=(object_pool &&other) = delete;

    private:
        std::mutex m_mutex {};
        std::mutex m_free_list_mutex {};

        union node {
            node* next;
            alignas(value_type) char storage[sizeof(value_type)];
        };

        struct chunk {
            std::unique_ptr<node[]> blocks;
            constexpr explicit chunk(const std::size_t capacity) noexcept
            : blocks {new node[capacity]} {}
        };

        std::vector<chunk> m_pool {};
        std::atomic<std::size_t> current_chunk_index {0};
        std::size_t m_chunk_capacity;
        node* free_list {nullptr};

        explicit constexpr object_pool(std::size_t chunk_capacity = 4096) noexcept
        : m_chunk_capacity(chunk_capacity) {
            m_pool.emplace_back(chunk_capacity);
        }

        void release(pointer p) {
            if (!p) return;
            p->~value_type();

            node* block = reinterpret_cast<node*>(p);

            std::scoped_lock lock(m_free_list_mutex);
            block->next = free_list;
            free_list = block;
        }
    };
#endif

    using object_pool_t = object_pool<std::vector<u8>>;
} // net

#endif //OBJECT_POOL_H
