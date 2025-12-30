//
// Created by inquaterni on 12/30/25.
//

#ifndef CONTEXT_H
#define CONTEXT_H

namespace enet {

    class context {
    public:
        ~context();

        static context &get_instance() noexcept;
        static bool is_initialized() noexcept;

        context(const context &other) = delete;
        context &operator=(const context &other) = delete;
        context(context &&other) = delete;
        context &operator=(context &&other) = delete;

    private:
        static constinit inline bool initialized{false};
        context();
    };

} // namespace enet

#endif // CONTEXT_H
