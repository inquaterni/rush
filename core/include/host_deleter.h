//
// Created by inquaterni on 12/30/25.
//

#ifndef HOST_DELETER_H
#define HOST_DELETER_H

#include "enet.h"

namespace enet {

    class host_deleter {
    public:
        void operator()(ENetHost *host_ptr) const {
            if (host_ptr) {
                enet_host_destroy(host_ptr);
            }
        }
    };

} // namespace enet

#endif // HOST_DELETER_H
