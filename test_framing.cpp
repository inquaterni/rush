#include <capnp/message.h>
#include <capnp/serialize.h>
#include <iostream>
#include <iomanip>
#include <vector>

int main() {
    std::vector<uint8_t> buf;
    buf.resize(256);
    
    capnp::word* out_words = reinterpret_cast<capnp::word*>(buf.data());
    auto word_span = kj::arrayPtr(out_words + 1, (buf.size() / sizeof(capnp::word)) - 1);
    
    capnp::FlatMessageBuilder message(word_span);
    // Simulate initRoot with a simple struct
    auto root = message.initRoot<capnp::AnyPointer>();
    auto structBuilder = root.initAs<capnp::Data>(8);
    
    auto segments = message.getSegmentsForOutput();
    
    auto* table = reinterpret_cast<uint8_t*>(out_words);
    table[0] = 0; table[1] = 0; table[2] = 0; table[3] = 0;
    uint32_t size = segments[0].size();
    table[4] = size & 0xFF; table[5] = (size >> 8) & 0xFF;
    table[6] = (size >> 16) & 0xFF; table[7] = (size >> 24) & 0xFF;
    
    buf.resize((1 + size) * sizeof(capnp::word));
    
    std::cout << "Buffer size: " << buf.size() << " bytes, " << buf.size() / 8 << " words." << std::endl;
    for (size_t i = 0; i < buf.size() / 8; ++i) {
        uint8_t const* bytes = reinterpret_cast<uint8_t const*>(buf.data() + i * 8);
        for (int j = 0; j < 8; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[j] << " ";
        }
        std::cout << "  (word " << i << ")" << std::endl;
    }
    
    // Now try to read it
    try {
        auto read_span = kj::arrayPtr(reinterpret_cast<const capnp::word*>(buf.data()), buf.size() / 8);
        capnp::FlatArrayMessageReader reader(read_span);
        std::cout << "Successfully read message!" << std::endl;
    } catch (const kj::Exception& e) {
        std::cout << "Failed to read: " << e.getDescription().cStr() << std::endl;
    }
    return 0;
}
