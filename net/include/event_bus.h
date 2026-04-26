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
#ifndef EVENT_BUS_H
#define EVENT_BUS_H
#include <array>
#include <optional>
#include <variant>
#define RUSH_ALIGNED_CAPACITY(T, MinCapacity) \
    (alignof(T) > (MinCapacity) ? alignof(T) :   \
     ((MinCapacity) < 4 ? 4 : (((MinCapacity) & ((MinCapacity) - 1)) == 0 \
         ? (MinCapacity) * 2 : [] { \
             std::size_t v = (MinCapacity); \
             v |= v >> 1; v |= v >> 2; v |= v >> 4; \
             v |= v >> 8; v |= v >> 16; \
             return v + 1; \
         }())))
namespace net {
    template <typename T, std::size_t N>
    class event_bus {
    public:
        using value_type = T;
        using size_type = std::size_t;
        constexpr event_bus() noexcept = default;
        event_bus(const event_bus&) = delete;
        event_bus& operator=(const event_bus&) = delete;
        event_bus(event_bus&&) = delete;
        event_bus& operator=(event_bus&&) = delete;
        static constexpr event_bus& instance() noexcept {
            static event_bus bus {};
            return bus;
        }
        constexpr bool enqueue(const std::initializer_list<T> &list) noexcept {
            if (m_size == N) return false;
            auto val = T {list.begin(), list.end()};
            tail = (tail + 1) % N;
            ++m_size;
            return val;
        }
        template<typename ...Args>
        constexpr bool enqueue(Args&&... args) noexcept {
            if (m_size == N) return false;
            buf[tail] = T {std::forward<Args>(args)...};
            tail = (tail + 1) % N;
            ++m_size;
            return true;
        }
        template<typename ...Args>
        constexpr bool create_enqueue(Args&&... args) noexcept {
            if (m_size == N) return false;
            std::optional<T> val;
            if constexpr (requires { T::create(std::forward<Args>(args)...); }) {
                auto res = T::create(std::forward<Args>(args)...);
                if constexpr (requires { res.operator bool(); }) {
                    if (res) val = std::move(*res);
                } else {
                    val = std::move(res);
                }
            } else if constexpr (requires { []<typename... Alts>(std::variant<Alts...>*) {}(static_cast<T*>(nullptr)); }) {
                val = [&]<typename... Alts>(std::variant<Alts...>*) {
                    std::optional<std::variant<Alts...>> res;
                    (..., (
                        [&] constexpr {
                            if constexpr (requires { Alts::create(std::forward<Args>(args)...); }) {
                                auto exp = Alts::create(std::forward<Args>(args)...);
                                if constexpr (requires { exp.operator bool(); }) {
                                    if (exp) res = std::move(*exp);
                                } else {
                                    res = std::move(exp);
                                }
                            }
                        }()
                    ));
                    return res;
                }(static_cast<T*>(nullptr));
            }
            if (!val) return false;
            
            buf[tail] = std::move(*val);
            tail = (tail + 1) % N;
            ++m_size;
            return true;
        }
        constexpr bool enqueue(T value) noexcept {
            if (m_size == N) return false;
            buf[tail] = std::move(value);
            tail = (tail + 1) % N;
            ++m_size;
            return true;
        }
        constexpr std::optional<T> dequeue() noexcept {
            if (m_size == 0) return std::nullopt;
            auto val = std::move(buf[head].value());
            head = (head + 1) % N;
            --m_size;
            return val;
        }
        [[nodiscard]] constexpr const T* peek() const noexcept {
            if (m_size == 0) return nullptr;
            return &buf[head].value();
        }
        [[nodiscard]] constexpr std::size_t        size()     const noexcept { return m_size; }
        [[nodiscard]] constexpr bool               empty()    const noexcept { return m_size == 0; }
        [[nodiscard]] constexpr bool               full()     const noexcept { return m_size == N; }
        [[nodiscard]] static constexpr std::size_t capacity() noexcept { return N; }
        constexpr void clear() noexcept {
            head = 0;
            tail = 0;
            m_size = 0;
        }
    private:
        std::array<std::optional<T>, N> buf {};
        std::size_t head {0};
        std::size_t tail {0};
        std::size_t m_size {0};
    };
} // net
#endif //EVENT_BUS_H
