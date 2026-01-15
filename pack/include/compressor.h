//
// Created by inquaterni on 1/14/26.
//

#ifndef COMPRESSOR_H
#define COMPRESSOR_H
#include <expected>
#include <span>
#include <string>
#include <vector>
#include <zstd.h>



namespace pack {
    class compressor {
    public:
        compressor() noexcept = default;
        ~compressor() noexcept = default;

        [[nodiscard]]
        static constexpr std::expected<std::vector<unsigned char>, std::string>
        compress(const std::vector<unsigned char> & /* data */, int compression_level = 5) noexcept;
        [[nodiscard]]
        static constexpr std::expected<std::vector<unsigned char>, std::string>
        compress(const std::span<const unsigned char> & /* data */, int compression_level = 5) noexcept;
        [[nodiscard]]
        static constexpr std::expected<std::vector<unsigned char>, std::string>
        decompress(const std::vector<unsigned char> & /* data */) noexcept;
        [[nodiscard]]
        static constexpr std::expected<std::vector<unsigned char>, std::string>
        decompress(const std::span<const unsigned char> & /* data */) noexcept;

        [[nodiscard]]
        static constexpr std::size_t estimate_compressed_size(const std::vector<unsigned char> & /* data */) noexcept;
        static constexpr std::size_t estimate_compressed_size(const std::span<const unsigned char> & /* data */) noexcept;
    };
    constexpr std::expected<std::vector<unsigned char>, std::string>
    compressor::compress(const std::vector<unsigned char> &data, const int compression_level) noexcept {
        const std::size_t max_compressed_size = estimate_compressed_size(data);
        std::vector<unsigned char> compressed;
        compressed.resize(max_compressed_size);

        const std::size_t compressed_size =
                ZSTD_compress(compressed.data(), compressed.capacity(), data.data(), data.size(), compression_level);

        if (const auto err = ZSTD_isError(compressed_size); err) {
            return std::unexpected{"Zstd comression error: " + std::string(ZSTD_getErrorName(err))};
        }

        compressed.resize(compressed_size);
        return compressed;
    }
    constexpr std::expected<std::vector<unsigned char>, std::string>
    compressor::compress(const std::span<const unsigned char> &data, const int compression_level) noexcept {
        const std::size_t max_compressed_size = estimate_compressed_size(data);
        std::vector<unsigned char> compressed;
        compressed.resize(max_compressed_size);

        const std::size_t compressed_size =
                ZSTD_compress(compressed.data(), compressed.capacity(), data.data(), data.size(), compression_level);

        if (const auto err = ZSTD_isError(compressed_size); err) {
            return std::unexpected{"Zstd comression error: " + std::string(ZSTD_getErrorName(err))};
        }

        compressed.resize(compressed_size);
        return compressed;
    }
    constexpr std::expected<std::vector<unsigned char>, std::string>
    compressor::decompress(const std::vector<unsigned char> &data) noexcept {
        std::vector<unsigned char> decompressed;

        const auto compressed_size = ZSTD_getFrameContentSize(data.data(), data.size());
        if (const auto err = ZSTD_isError(compressed_size); err) {
            return std::unexpected{"Zstd frame content size calc error: " + std::string(ZSTD_getErrorName(err))};
        }

        decompressed.resize(compressed_size);
        const auto decompressed_size =
                ZSTD_decompress(decompressed.data(), decompressed.capacity(), data.data(), data.size());

        if (const auto err = ZSTD_isError(decompressed_size); err) {
            return std::unexpected{"Zstd decompression error: " + std::string(ZSTD_getErrorName(err))};
        }

        decompressed.resize(decompressed_size);
        return decompressed;
    }
    constexpr std::expected<std::vector<unsigned char>, std::string>
    compressor::decompress(const std::span<const unsigned char> &data) noexcept {
        std::vector<unsigned char> decompressed;

        const auto compressed_size = ZSTD_getFrameContentSize(data.data(), data.size());
        if (const auto err = ZSTD_isError(compressed_size); err) {
            return std::unexpected{"Zstd frame content size calc error: " + std::string(ZSTD_getErrorName(err))};
        }

        decompressed.resize(compressed_size);
        const auto decompressed_size =
                ZSTD_decompress(decompressed.data(), decompressed.capacity(), data.data(), data.size());

        if (const auto err = ZSTD_isError(decompressed_size); err) {
            return std::unexpected{"Zstd decompression error: " + std::string(ZSTD_getErrorName(err))};
        }

        decompressed.resize(decompressed_size);
        return decompressed;
    }
    constexpr std::size_t compressor::estimate_compressed_size(const std::vector<unsigned char> &data) noexcept {
        return ZSTD_compressBound(data.size());
    }
    constexpr std::size_t compressor::estimate_compressed_size(const std::span<const unsigned char> &data) noexcept {
        return ZSTD_compressBound(data.size());
    }

} // pack

#endif //COMPRESSOR_H
