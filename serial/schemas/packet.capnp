@0xd2fffa5d7bd03a92;

enum PacketType {
    handshakeClient @0;
    handshakeServer @1;
    raw @2;
    compressedZstd @3;
    encryptedChacha20Poly1305 @4;
}

struct Packet {
    type @0 :PacketType;

    body :union {
        handshakeClient @1 :Handshake;
        handshakeServer @2 :Handshake;
        generic @3 :Data;
    }
}

struct Handshake {
    publicKey @0 :Data; 
}
