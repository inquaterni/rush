@0xd2fffa5d7bd03a92;

struct Packet {
    union {
        handshake @0 :Handshake;
        bytes @1 :Data;
        disconnect @2 :Data;
        signal @3 :Data;
        authRequest @4 :Auth;
        authResponse @5: Data;
        resize @6 :Winsize;
    }
}

struct Winsize {
    wsRow    @0 :UInt16;
    wsCol    @1 :UInt16;
    wsXpixel @2 :UInt16;
    wsYpixel @3 :UInt16;
}
struct Auth {
    username @0 :Text;
    passwd @1 :Text;
}
struct Handshake {
    publicKey @0 :Data;
}
