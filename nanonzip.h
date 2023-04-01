/// @file
/// @brief  nanonzip.h
/// @author (C) 2023 ttsuki
/// MIT License

#pragma once
#ifndef NANONZIP_H_INCLUDED
#define NANONZIP_H_INCLUDED

//#define NANONZIP_ENABLE_ZLIB
//#define NANONZIP_ENABLE_BZIP2

#include <cstddef>
#include <cstdint>
#include <ctime>

#include <memory>
#include <string_view>
#include <istream>
#include <fstream>
#include <filesystem>
#include <functional>
#include <stdexcept>
#include <vector>
#include <utility>
#include <mutex>

namespace nanonzip
{
    /// Represents a file header in zip file.
    struct file_header
    {
        enum struct compression_method_t : std::uint16_t
        {
            stored = 0,
            deflate = 8,
            bzip2 = 12,
        };

        uint16_t general_purpose_bit_flag{};
        compression_method_t compression_method{};
        uint32_t crc_32{};
        std::time_t last_mod_timestamp{};
        std::streamoff uncompressed_size{};
        std::streamoff compressed_size{};
        std::streamoff relative_offset_of_local_header{};
        std::filesystem::path path{};
    };

    /// Represents a file stream in zip file.
    class file
    {
    public:
        using file_read_function = std::function<size_t(void* buf, size_t len)>;

        file() = default;
        file(file_header header, file_read_function read) : header_(std::move(header)), read_(std::move(read)) { }
        file(const file& other) = delete;
        file(file&& other) noexcept = default;
        file& operator=(const file& other) = delete;
        file& operator=(file&& other) noexcept = default;
        ~file() = default;

        [[nodiscard]] const file_header& header() const noexcept { return header_; }
        [[nodiscard]] const std::filesystem::path& path() const noexcept { return header_.path; }
        [[nodiscard]] const std::streamoff& size() const noexcept { return header_.uncompressed_size; }
        [[nodiscard]] size_t read(void* buffer, size_t size) { return read_(buffer, size); }

    private:
        file_header header_{};
        file_read_function read_{};
    };

    /// Function reads the file `len` bytes from the position represented by `cursor` and stores into `buf`, then returns `len`
    using file_seek_read_function = std::function<int(std::streamoff cursor, void* buf, int len)>;

    /// ZIP file reader
    class zip_file_reader
    {
    public:
        zip_file_reader() = default;

        /// Opens and parses a zip file from stream function.
        zip_file_reader(file_seek_read_function zip_file, std::streamoff length);

        /// Opens and parses a zip file.
        zip_file_reader(const std::filesystem::path& zip_file);

        /// Opens and parses a zip file from istream.
        zip_file_reader(const std::shared_ptr<std::istream>& zip_file);

        /// Opens and parses a zip file from istream.
        zip_file_reader(const std::shared_ptr<std::istream>& zip_file, std::streamoff length);

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
        file_seek_read_function read_zip_file_{};
        std::vector<file_header> central_directory_{};
        [[nodiscard]] file open_file_stream(const file_header& file_header, std::string_view password) const;
    };

    /// a sample of istream interface
    struct istream
    {
        void read(void* s, int n);
        void seekg(std::streamoff pos);
    };

    /// Makes thread-safe file_seek_read_function from std::istream-like implementation.
    template <class istream>
    static file_seek_read_function make_file_seek_read_function_for_istream(std::shared_ptr<istream> stream, std::streamoff total_length)
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

    inline zip_file_reader::zip_file_reader(const std::filesystem::path& zip_file) : zip_file_reader(std::make_shared<std::ifstream>(zip_file, std::ios::in | std::ios::binary)) { }
    inline zip_file_reader::zip_file_reader(const std::shared_ptr<std::istream>& zip_file) : zip_file_reader(zip_file, static_cast<std::streamoff>(zip_file->seekg(0, std::ios::end).tellg())) { }
    inline zip_file_reader::zip_file_reader(const std::shared_ptr<std::istream>& zip_file, std::streamoff length) : zip_file_reader(nanonzip::make_file_seek_read_function_for_istream<std::istream>(zip_file, length), length) { }

    using compression_method_t = file_header::compression_method_t;
}

#endif // #ifndef NANONZIP_H_INCLUDED
