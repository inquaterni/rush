//
// Created by inquaterni on 3/30/26.
//

#ifndef OBJECT_POOL_H
#define OBJECT_POOL_H
#include <memory>
#include <mutex>
#include <vector>

namespace net {

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
        constexpr pool_ptr acquire(Args&&... args) {
            pointer raw {nullptr};
            {
                std::scoped_lock lock(m_mutex);

                if (free_list) {
                    node *block = free_list;
                    free_list = free_list->next;
                    raw = new (block->storage) value_type(std::forward<Args>(args)...);
                } else {
                    if (current_chunk_index >= m_chunk_capacity) {
                        m_pool.emplace_back(m_chunk_capacity);
                        current_chunk_index = 0;
                    }
                    node *block = &m_pool.back().blocks[current_chunk_index++];
                    raw = new (block->storage) value_type(std::forward<Args>(args)...);
                }
            }
            return pool_ptr {raw, [](T *p) constexpr {
                get_instance().release(p);
            }};
        }

        constexpr pool_ptr acquire() {
            pointer raw {nullptr};
            {
                std::scoped_lock lock(m_mutex);

                if (free_list) {
                    node *block = free_list;
                    free_list = free_list->next;
                    raw = new (block->storage) value_type();
                } else {
                    if (current_chunk_index >= m_chunk_capacity) {
                        m_pool.emplace_back(m_chunk_capacity);
                        current_chunk_index = 0;
                    }
                    node *block = &m_pool.back().blocks[current_chunk_index++];
                    raw = new (block->storage) value_type();
                }
            }
            return pool_ptr {raw, [](T *p) constexpr {
                get_instance().release(p);
            }};
        }

        constexpr std::size_t capacity() {
            std::scoped_lock lock(m_mutex);
            return m_pool.size() * m_chunk_capacity;
        }

        constexpr object_pool(const object_pool &other) = delete;
        constexpr object_pool &operator=(const object_pool &other) = delete;
        constexpr object_pool(object_pool &&other) = delete;
        constexpr object_pool &operator=(object_pool &&other) = delete;

    private:
        std::mutex m_mutex {};

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
        std::size_t current_chunk_index {0};
        std::size_t m_chunk_capacity;
        node* free_list {nullptr};

        explicit constexpr object_pool(std::size_t chunk_capacity = 4096) noexcept
        : m_chunk_capacity(chunk_capacity) {
            m_pool.emplace_back(chunk_capacity);
        }

        constexpr void release(pointer p) {
            if (!p) return;

            p->~value_type();

            {
                std::scoped_lock lock(m_mutex);
                node *block = reinterpret_cast<node *>(p);
                block->next = free_list;
                free_list = block;
            }
        }
    };

} // net

#endif //OBJECT_POOL_H
