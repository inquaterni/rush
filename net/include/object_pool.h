// Copyright (c) 2026 Maksym Matskevych
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#ifndef OBJECT_POOL_H
#define OBJECT_POOL_H
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>
#include "types.h"
namespace net {
    // Tagged pointer structure:
    // Bits:
    //  128                    64 63                    0
    // ┌───────────────────────┬────────────────────────┐
    // │  tag                  │       pointer          │
    // └───────────────────────┴────────────────────────┘
    template<typename T>
    struct alignas(16) tagged_ptr {
        using pointer = T*;
        static tagged_ptr make(T* ptr, const u64 tag = 0) noexcept{
            return tagged_ptr {ptr, tag};
        }
        pointer ptr() const noexcept {
            return m_ptr;
        }
        [[nodiscard]]
        u64 tag() const noexcept {
            return m_tag;
        }
        tagged_ptr bumped() const noexcept {
            return tagged_ptr{m_ptr, m_tag + 1};
        }
        explicit constexpr tagged_ptr(T* ptr) noexcept: m_ptr {ptr} {}
        explicit constexpr tagged_ptr(T* ptr, const u64 tag) noexcept: m_tag{tag}, m_ptr{ptr} {}
        constexpr tagged_ptr() noexcept: m_ptr {nullptr} {}
    private:
        u64 m_tag{};
        pointer m_ptr;
    };
    template<typename T>
    class object_pool {
    public:
        using value_type = T;
        using pointer = T *;
        using pool_ptr = std::unique_ptr<value_type, void(*)(value_type*) noexcept>;

        static constexpr object_pool &get_instance() noexcept {
            static object_pool instance {};
            return instance;
        }
        template<typename... Args>
        [[nodiscard]]
        constexpr pool_ptr acquire(Args&&... args) noexcept {
            static constexpr auto deleter = [](T* p) noexcept { get_instance().release(p); };

            pointer raw {nullptr};
            node_tptr old_head = free_list.load(std::memory_order_acquire);
            while (old_head.ptr()) {
                if (node_tptr new_head = node_tptr::make(old_head.ptr()->next, old_head.tag() + 1);
                    free_list.compare_exchange_weak(old_head, new_head,
                        std::memory_order_acquire,
                        std::memory_order_relaxed)) {
                    raw = new (old_head.ptr()->storage) value_type(std::forward<Args>(args)...);
                    return pool_ptr {raw, deleter};
                }
            }
            {
                std::scoped_lock lock(m_mutex);
                if (current_chunk_index >= m_chunk_capacity) {
                    m_pool.emplace_back(m_chunk_capacity);
                    current_chunk_index = 0;
                }
                node* block = &m_pool.back().blocks[current_chunk_index++];
                raw = new (block->storage) value_type(std::forward<Args>(args)...);
            }
            return pool_ptr {raw, deleter};
        }
        constexpr std::size_t capacity() noexcept {
            std::scoped_lock lock(m_mutex);
            return m_pool.size() * m_chunk_capacity;
        }
        constexpr object_pool(const object_pool &other) = delete;
        constexpr object_pool &operator=(const object_pool &other) = delete;
        constexpr object_pool(object_pool &&other) = delete;
        constexpr object_pool &operator=(object_pool &&other) = delete;
        constexpr void release(pointer p) noexcept {
            if (!p) return;
            p->~value_type();
            node* block = std::launder(
                static_cast<node*>(static_cast<void*>(p))
            );
            node_tptr old_head = free_list.load(std::memory_order_relaxed);
            node_tptr new_head;
            do {
                block->next = old_head.ptr();
                new_head = node_tptr::make(block, old_head.tag() + 1);
            } while (!free_list.compare_exchange_weak(old_head, new_head,
                std::memory_order_release,
                std::memory_order_relaxed)
                );
        }
    private:
        std::mutex m_mutex {};
        union node {
            alignas(value_type) std::byte storage[sizeof(value_type)];
            node* next;
        };
        using node_tptr = tagged_ptr<node>;
        struct chunk {
            std::unique_ptr<node[]> blocks;
            constexpr explicit chunk(const std::size_t capacity) noexcept
            : blocks {new node[capacity]} {}
        };
        std::vector<chunk> m_pool {};
        std::size_t current_chunk_index {0};
        std::size_t m_chunk_capacity;
        std::atomic<node_tptr> free_list {node_tptr::make(nullptr)};
        explicit constexpr object_pool(std::size_t chunk_capacity = 4096) noexcept
        : m_chunk_capacity(chunk_capacity) {
            m_pool.emplace_back(chunk_capacity);
        }
    };

    using object_pool_t = object_pool<std::vector<u8>>;
} // net
#endif //OBJECT_POOL_H
