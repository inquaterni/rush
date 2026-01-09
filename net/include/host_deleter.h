//
// Created by inquaterni on 12/30/25.
//

#ifndef HOST_DELETER_H
#define HOST_DELETER_H

#include "enet.h"

namespace net {

    class host_deleter {
    public:
        void operator()(ENetHost *host_ptr) const {
            if (host_ptr) {
                enet_host_destroy(host_ptr);
            }
        }
    };

} // net

#endif // HOST_DELETER_H
