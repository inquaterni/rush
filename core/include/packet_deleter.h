//
// Created by inquaterni on 12/31/25.
//

#ifndef PACKET_DELETER_H
#define PACKET_DELETER_H
#include "enet.h"

namespace enet {

class packet_deleter {
public:
    void operator()(ENetPacket *packet_ptr) const {
        if (packet_ptr) {
            enet_packet_destroy(packet_ptr);
        }
    }

};

} // enet

#endif //PACKET_DELETER_H
