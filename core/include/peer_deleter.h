//
// Created by inquaterni on 12/31/25.
//

#ifndef PEER_DELETER_H
#define PEER_DELETER_H
#include "enet.h"

namespace enet {
    class peer_deleter {
    public:
        void operator()(ENetPeer *peer_ptr) const {
            if (peer_ptr) {
                enet_peer_reset(peer_ptr);
            }
        }
    };
}

#endif //PEER_DELETER_H
