@0xd2fffa5d7bd03a92;

struct Packet {
    union {
        handshake @0 :Handshake;
        stdin @1 :Data;
        signal @2 :Data;
        resize @3 :Winsize;
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
