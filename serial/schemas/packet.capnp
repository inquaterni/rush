@0xd2fffa5d7bd03a92;

struct Packet {
    union {
        handshake @0 :Handshake;
        bytes @1 :Data;
        disconnect @2 :Data;
        signal @3 :Data;
        resize @4 :Winsize;
    }
}

struct Winsize {
  wsRow    @0 :UInt16;
  wsCol    @1 :UInt16;
  wsXpixel @2 :UInt16;
  wsYpixel @3 :UInt16;
}
struct Handshake {
    publicKey @0 :Data;
}
