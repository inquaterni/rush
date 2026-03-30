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

        static constexpr object_pool &get_instance() noexcept {
            static object_pool instance {};
            return instance;
        }

        constexpr std::shared_ptr<value_type> acquire() {
            T *raw {nullptr};
            {
                std::scoped_lock lock(m_mutex);
                if (!m_pool.empty()) {
                    raw = m_pool.back().release();
                    m_pool.pop_back();
                } else {
                    raw = new T {};
                }
            }
            return std::shared_ptr<value_type>{raw, [](T *p) constexpr {
                get_instance().release(p);
            }};
        }
        constexpr void reserve(const std::size_t count) {
            m_pool.reserve(count);
        }
        constexpr void resize(const std::size_t count, const value_type &value) {
            m_pool.resize(count, value);
        }
        constexpr std::size_t size() {
            return m_pool.size();
        }

        constexpr object_pool(const object_pool &other) = delete;
        constexpr object_pool &operator=(const object_pool &other) = delete;
        constexpr object_pool(object_pool &&other) = delete;
        constexpr object_pool &operator=(object_pool &&other) = delete;

    private:
        std::mutex m_mutex {};
        std::vector<std::unique_ptr<value_type>> m_pool {};

        constexpr object_pool() = default;

        constexpr void release(T *obj) {
            std::scoped_lock lock(m_mutex);
            m_pool.emplace_back(obj);
        }
    };

} // net

#endif //OBJECT_POOL_H
