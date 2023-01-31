/// @file
/// @brief  nanonzip.h
/// @author (C) 2023 ttsuki
/// MIT License

#pragma once
#ifndef NANONZIP_H_INCLUDED
#define NANONZIP_H_INCLUDED

//#define NANONZIP_ENABLE_ZLIB
//#define NANONZIP_ENABLE_BZIP2

#include <cstring>
#include <cstdint>
#include <cstddef>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nanonzip
{
    struct local_file_header;
    struct central_directory_header;
    struct zip64_end_of_central_directory_record;
    struct zip64_end_of_central_directory_locator;
    struct end_of_central_directory_record;

    enum struct compression_method_t : uint16_t
    {
        stored = 0,
        deflate = 8,
        bzip2 = 12,
    };

    /// Represents a file header in zip file.
    struct file_header
    {
        uint16_t general_purpose_bit_flag{};
        compression_method_t compression_method{};
        uint32_t crc_32{};
        std::time_t last_mod_timestamp{};
        std::streamoff uncompressed_size{};
        std::streamoff compressed_size{};
        std::streamoff relative_offset_of_local_header{};
        std::filesystem::path path{};
        [[nodiscard]] static file_header from_central_directory_header(const central_directory_header* cdh);
    };

    /// Represents a file in zip file.
    class file
    {
        file_header header_;
        std::function<size_t(void* buf, size_t len)> read_{};

    public:
        file() = default;

        file(file_header header, std::function<size_t(void* buf, size_t len)> read)
            : header_(std::move(header)), read_(std::move(read)) { }

        file(const file& other) = delete;
        file(file&& other) noexcept = default;
        file& operator=(const file& other) = delete;
        file& operator=(file&& other) noexcept = default;
        ~file() = default;

        [[nodiscard]] const file_header& header() const noexcept { return header_; }
        [[nodiscard]] const std::filesystem::path& path() const noexcept { return header_.path; }
        [[nodiscard]] const std::streamoff& size() const noexcept { return header_.uncompressed_size; }
        [[nodiscard]] size_t read(void* buffer, size_t size) { return read_(buffer, size); }
    };

    /// Reads the file `len` bytes from the position represented by `cursor` and stores into `buf`, then returns `len`
    using seek_and_read_file_function = std::function<int(std::streamoff cursor, void* buf, int len)>;

    /// a sample of istream interface
    struct istream
    {
        void read(void* s, int n);
        void seekg(std::streamoff pos);
    };

    /// Makes thread-safe seek_and_read_file_function from std::istream-like implementation.
    template <class istream>
    static seek_and_read_file_function make_seek_and_read_function_for_istream(
        std::shared_ptr<istream> stream,
        std::streamoff total_length)
    {
        return [mutex_ = std::make_shared<std::mutex>(), stream, total_length](std::streamoff cursor, void* buf, int size) mutable -> int
        {
            std::lock_guard lock(*mutex_);
            if (cursor + size > total_length) throw std::out_of_range("cursor + size > total_length");
            stream->seekg(cursor);
            stream->read(static_cast<char*>(buf), size);
            cursor += size;
            return size;
        };
    }

    /// ZIP file reader
    class zip_file_reader
    {
    public:
        zip_file_reader() = default;

        /// Opens and parses a zip file.
        zip_file_reader(const std::filesystem::path& zip_file)
            : zip_file_reader(std::make_shared<std::ifstream>(zip_file, std::ios::in | std::ios::binary)) { }

        /// Opens and parses a zip file from istream.
        zip_file_reader(const std::shared_ptr<std::istream>& zip_file)
            : zip_file_reader(zip_file, static_cast<std::streamoff>(zip_file->seekg(0, std::ios::end).tellg())) { }

        /// Opens and parses a zip file from istream.
        zip_file_reader(const std::shared_ptr<std::istream>& zip_file, std::streamoff length)
            : zip_file_reader(nanonzip::make_seek_and_read_function_for_istream<std::istream>(zip_file, length), length) { }

        /// Opens and parses a zip file from stream function.
        zip_file_reader(seek_and_read_file_function zip_file, std::streamoff length);

        zip_file_reader(const zip_file_reader& other) = delete;
        zip_file_reader(zip_file_reader&& other) noexcept = default;
        zip_file_reader& operator=(const zip_file_reader& other) = delete;
        zip_file_reader& operator=(zip_file_reader&& other) noexcept = default;
        ~zip_file_reader() = default;

        /// Gets parsed central directory.
        [[nodiscard]] const std::vector<file_header>& files() const noexcept { return central_directory_; }

        /// Opens file stream in archive for read.
        // the thread-safety of between files is guaranteed if base seek_and_read_file_function provides thread-safety.
        [[nodiscard]] file open_file(const std::filesystem::path& path, std::string_view password = {}) const
        {
            for (const auto& f : files())
                if (path == f.path)
                    return open_file_stream(f, password);

            throw std::runtime_error("no such file.");
        }

        /// Opens file stream in archive for read.
        // the thread-safety of between files is guaranteed if base seek_and_read_file_function provides thread-safety.
        [[nodiscard]] file open_file_by_index(size_t index, std::string_view password = {}) const
        {
            if (index < files().size())
                return open_file_stream(files()[index], password);

            throw std::runtime_error("no such file.");
        }

    private:
        using ssize32_t = int32_t;
        struct decrypt_impl;
        struct zlib_inflate_impl;
        struct bzip2_decompress_impl;

        seek_and_read_file_function read_zip_file_{};
        std::vector<file_header> central_directory_{};

        /// Open a file stream in zip file.
        [[nodiscard]] file open_file_stream(const file_header& file_header, std::string_view password) const;
    };
}

#endif // #ifndef NANONZIP_H_INCLUDED
