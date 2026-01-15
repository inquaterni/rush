@0xd2fffa5d7bd03a92;

struct Packet {
    union {
        handshake @0 :Handshake;
        xchacha20Poly1305 @1 :Data;
    }
}

struct Handshake {
    publicKey @0 :Data;
}
