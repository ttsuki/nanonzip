/// @file
/// @brief  nanonzip.cpp
/// @author (C) 2023 ttsuki
/// MIT License

#include "nanonzip.h"

#ifndef NANONZIP_EXPORT
#define NANONZIP_EXPORT
#endif

#ifdef NANONZIP_ENABLE_ZLIB
#include <zlib.h>
#endif

#ifdef NANONZIP_ENABLE_BZIP2
#include <bzlib.h>
#endif

namespace nanonzip
{
#pragma pack(push, 1)

    struct header_extra_field
    {
        uint16_t tag;
        uint16_t size;
        [[nodiscard]] const std::byte* data() const noexcept { return reinterpret_cast<const std::byte*>(this + 1); }

        [[nodiscard]] static const header_extra_field* find_from_field(const std::string_view& sv, uint16_t signature)
        {
            size_t offset = 0;
            while (offset + 4 <= sv.length())
            {
                uint16_t tag = reinterpret_cast<const uint16_t*>(sv.data() + offset)[0];
                uint16_t size = reinterpret_cast<const uint16_t*>(sv.data() + offset)[1];
                if (tag == signature && offset + 4 + size <= sv.size()) return reinterpret_cast<const header_extra_field*>(sv.data() + offset);
                offset += 4 + size;
            }
            return nullptr;
        }
    };

    struct local_file_header
    {
        static inline constexpr uint32_t SIGNATURE = 0x04034b50;
        uint32_t local_file_header_signature; // 0x04034b50
        uint16_t version_needed_to_extract;
        uint16_t general_purpose_bit_flag;
        uint16_t compression_method;
        uint16_t last_mod_file_time;
        uint16_t last_mod_file_date;
        uint32_t crc_32;
        uint32_t compressed_size;
        uint32_t uncompressed_size;
        uint16_t filename_length;
        uint16_t extra_field_length;
        [[nodiscard]] static constexpr size_t fixed_header_size() { return 30; }
        [[nodiscard]] std::string_view filename() const { return {reinterpret_cast<const char*>(this) + fixed_header_size(), filename_length}; }
        [[nodiscard]] std::string_view extra_field() const { return {reinterpret_cast<const char*>(this) + fixed_header_size() + filename_length, extra_field_length}; }
        [[nodiscard]] size_t total_header_size() const { return fixed_header_size() + filename_length + extra_field_length; }
        [[nodiscard]] const header_extra_field* find_extra_field(uint16_t signature) const noexcept { return header_extra_field::find_from_field(extra_field(), signature); }
    };

    struct central_directory_header
    {
        static inline constexpr uint32_t SIGNATURE = 0x02014b50;
        uint32_t central_file_header_signature; // 0x02014b50
        uint16_t version_made_by;
        uint16_t version_needed_to_extract;
        uint16_t general_purpose_bit_flag;
        uint16_t compression_method;
        uint16_t last_mod_file_time;
        uint16_t last_mod_file_date;
        uint32_t crc_32;
        uint32_t compressed_size;
        uint32_t uncompressed_size;
        uint16_t filename_length;
        uint16_t extra_field_length;
        uint16_t file_comment_length;
        uint16_t disk_number_start;
        uint16_t internal_file_attributes;
        uint32_t external_file_attributes;
        uint32_t relative_offset_of_local_header;
        [[nodiscard]] static constexpr size_t fixed_header_size() { return 46; }
        [[nodiscard]] std::string_view filename() const { return {reinterpret_cast<const char*>(this) + fixed_header_size(), filename_length}; }
        [[nodiscard]] std::string_view extra_field() const { return {reinterpret_cast<const char*>(this) + fixed_header_size() + filename_length, extra_field_length}; }
        [[nodiscard]] std::string_view file_comment() const { return {reinterpret_cast<const char*>(this) + fixed_header_size() + filename_length + extra_field_length, file_comment_length}; }
        [[nodiscard]] size_t total_header_size() const { return fixed_header_size() + filename_length + extra_field_length + file_comment_length; }
        [[nodiscard]] const header_extra_field* find_extra_field(uint16_t signature) const noexcept { return header_extra_field::find_from_field(extra_field(), signature); }
    };

    struct zip64_end_of_central_directory_record
    {
        static inline constexpr uint32_t SIGNATURE = 0x06064b50;
        uint32_t zip64_end_of_central_dir_signature; // 0x06064b50
        uint64_t size_of_zip64_end_of_central_directory_record;
        uint16_t version_made_by;
        uint16_t version_needed_to_extract;
        uint32_t number_of_this_disk;
        uint32_t number_of_the_disk_with_the_start_of_the_central_directory;
        uint64_t total_number_of_entries_in_the_central_directory_on_this_disk;
        uint64_t total_number_of_entries_in_the_central_directory;
        uint64_t size_of_the_central_directory;
        uint64_t offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number;
        [[nodiscard]] static constexpr size_t fixed_header_size() { return 56; }
        [[nodiscard]] size_t total_header_size() const { return fixed_header_size(); }
    };

    struct zip64_end_of_central_directory_locator
    {
        static inline constexpr uint32_t SIGNATURE = 0x07064b50;
        uint32_t zip64_end_of_central_dir_locator_signature; // 0x07064b50
        uint32_t number_of_the_disk_with_the_start_of_the_zip64_end_of_central_directory;
        uint64_t relative_offset_of_the_zip64_end_of_central_directory_record;
        uint32_t total_number_of_disks;
        [[nodiscard]] static constexpr size_t fixed_header_size() { return 20; }
        [[nodiscard]] size_t total_header_size() const { return fixed_header_size(); }
    };

    struct end_of_central_directory_record
    {
        static inline constexpr uint32_t SIGNATURE = 0x06054b50;
        uint32_t end_of_central_dir_signature; // 0x06054b50
        uint16_t number_of_this_disk;
        uint16_t number_of_the_disk_with_the_start_of_the_central_directory;
        uint16_t total_number_of_entries_in_the_central_directory_on_this_disk;
        uint16_t total_number_of_entries_in_the_central_directory;
        uint32_t size_of_the_central_directory;
        uint32_t offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number;
        uint16_t zip_file_comment_length;
        [[nodiscard]] static constexpr size_t fixed_header_size() { return 22; }
        [[nodiscard]] std::string_view file_comment() const { return {reinterpret_cast<const char*>(this) + fixed_header_size(), zip_file_comment_length}; }
        [[nodiscard]] size_t total_header_size() const { return fixed_header_size() + zip_file_comment_length; }
    };

    static_assert(sizeof(header_extra_field) == 4 && std::is_trivial_v<header_extra_field>);
    static_assert(sizeof(local_file_header) == local_file_header::fixed_header_size() && std::is_trivial_v<local_file_header>);
    static_assert(sizeof(central_directory_header) == central_directory_header::fixed_header_size() && std::is_trivial_v<central_directory_header>);
    static_assert(sizeof(zip64_end_of_central_directory_record) == zip64_end_of_central_directory_record::fixed_header_size() && std::is_trivial_v<zip64_end_of_central_directory_record>);
    static_assert(sizeof(zip64_end_of_central_directory_locator) == zip64_end_of_central_directory_locator::fixed_header_size() && std::is_trivial_v<zip64_end_of_central_directory_locator>);
    static_assert(sizeof(end_of_central_directory_record) == end_of_central_directory_record::fixed_header_size() && std::is_trivial_v<end_of_central_directory_record>);

#pragma pack(pop)

    NANONZIP_EXPORT file_header file_header::from_central_directory_header(const central_directory_header* cdh)
    {
        file_header r{};
        r.general_purpose_bit_flag = cdh->general_purpose_bit_flag;
        r.compression_method = static_cast<enum compression_method_t>(cdh->compression_method);
        r.crc_32 = cdh->crc_32;

        // last_mod_timestamp
        {
            std::tm tm{
                /* .tm_sec  = */ std::clamp((cdh->last_mod_file_time >> 0 & 0x1f) * 2, 0, 59),
                /* .tm_min  = */ std::clamp(cdh->last_mod_file_time >> 5 & 0x3f, 0, 59),
                /* .tm_hour = */ std::clamp(cdh->last_mod_file_time >> 11 & 0x1f, 0, 23),
                /* .tm_mday = */ std::clamp(cdh->last_mod_file_date >> 0 & 0x1f, 1, 31),
                /* .tm_mon  = */ std::clamp(cdh->last_mod_file_date >> 5 & 0x0f, 1, 12) - 1,
                /* .tm_year = */ std::clamp(cdh->last_mod_file_date >> 9 & 0x7f, 0, 128) + 1980 - 1900,
            };
            r.last_mod_timestamp = std::mktime(&tm);

            if (auto ut = cdh->find_extra_field(0x5455)) // Extended Timestamp Extra Field
            {
                ptrdiff_t t = 0;
                uint8_t flag{};
                if (t + sizeof(uint8_t) <= ut->size) flag = *reinterpret_cast<const uint8_t*>(ut->data() + std::exchange(t, t + sizeof(uint8_t)));
                if ((flag & 1) && t + sizeof(uint32_t) <= ut->size) r.last_mod_timestamp = static_cast<std::time_t>(*reinterpret_cast<const uint32_t*>(ut->data() + std::exchange(t, t + sizeof(uint32_t))));
            }
        }

        // uncompressed_size, compressed_size, relative_offset_of_local_header
        {
            r.uncompressed_size = cdh->uncompressed_size;
            r.compressed_size = cdh->compressed_size;
            r.relative_offset_of_local_header = cdh->relative_offset_of_local_header;

            if (auto zip64 = cdh->find_extra_field(0x0001)) // ZIP64 Extended Information Extra Field
            {
                ptrdiff_t t = 0;
                if (cdh->uncompressed_size == ~uint32_t{} && t + sizeof(uint64_t) <= zip64->size) r.uncompressed_size = static_cast<std::streamoff>(*reinterpret_cast<const uint64_t*>(zip64->data() + std::exchange(t, t + sizeof(uint64_t))));
                if (cdh->compressed_size == ~uint32_t{} && t + sizeof(uint64_t) <= zip64->size) r.compressed_size = static_cast<std::streamoff>(*reinterpret_cast<const uint64_t*>(zip64->data() + std::exchange(t, t + sizeof(uint64_t))));
                if (cdh->relative_offset_of_local_header == ~uint32_t{} && t + sizeof(uint64_t) <= zip64->size) r.relative_offset_of_local_header = static_cast<std::streamoff>(*reinterpret_cast<const uint64_t*>(zip64->data() + std::exchange(t, t + sizeof(uint64_t))));
            }
        }

        r.path = cdh->general_purpose_bit_flag & 1 << 11 // utf-8 encoding?
                     ? std::filesystem::u8path(cdh->filename())
                     : std::filesystem::path(cdh->filename());

        return r;
    }

    // Finds the end of central directory record from a zip file.
    template <class end_of_central_directory_record = end_of_central_directory_record>
    [[nodiscard]] static std::shared_ptr<const end_of_central_directory_record> find_end_of_central_directory_record(const seek_and_read_file_function& read_zip_file, std::streamoff total_zip_file_size)
    {
        // reads file from tail 
        constexpr int max_read_size_from_tail = 4096;
        std::string buffer(max_read_size_from_tail, '\0');
        {
            auto read_size = static_cast<int>(std::min<std::streamoff>(total_zip_file_size, max_read_size_from_tail));
            auto read_cursor = total_zip_file_size - read_size;
            read_zip_file(read_cursor, buffer.data() + max_read_size_from_tail - read_size, read_size);
        }

        // signature of "End of central directory record"
        const std::string end_of_central_directory_record_signature{
            static_cast<char>(end_of_central_directory_record::SIGNATURE & 0xFF),
            static_cast<char>(end_of_central_directory_record::SIGNATURE >> 8 & 0xFF),
            static_cast<char>(end_of_central_directory_record::SIGNATURE >> 16 & 0xFF),
            static_cast<char>(end_of_central_directory_record::SIGNATURE >> 24 & 0xFF),
        };

        // finds signature
        size_t found_offset{};
        if (found_offset = buffer.find(end_of_central_directory_record_signature, max_read_size_from_tail - 22); found_offset == std::string::npos)
            if (found_offset = buffer.find(end_of_central_directory_record_signature, max_read_size_from_tail - 256); found_offset == std::string::npos)
                if (found_offset = buffer.find(end_of_central_directory_record_signature, 0); found_offset == std::string::npos)
                    return nullptr; // throw std::runtime_error("failed to find end_of_central_directory_record");

        // allocates buffer
        const auto* found = reinterpret_cast<const end_of_central_directory_record*>(buffer.data() + found_offset);
        auto buf = std::shared_ptr(std::make_unique<char[]>(found->total_header_size()));
        std::memcpy(buf.get(), found, found->total_header_size());

        // rebinds pointer type
        return std::shared_ptr<end_of_central_directory_record>{buf, reinterpret_cast<end_of_central_directory_record*>(buf.get())};
    }

    // Reads the central directory from a zip file. 
    template <class end_of_central_directory_record = end_of_central_directory_record>
    [[nodiscard]] static std::vector<file_header> read_central_directory(const seek_and_read_file_function& read_zip_file, const end_of_central_directory_record* cd)
    {
        if (cd->size_of_the_central_directory > 1073741824) // 1GiB
            throw std::runtime_error("too large central directory");

        // reads whole central directory
        auto buffer = std::shared_ptr(std::make_unique<char[]>(cd->size_of_the_central_directory));
        {
            auto read_cursor = static_cast<std::streamoff>(cd->offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number);
            auto read_size = static_cast<int>(cd->size_of_the_central_directory);
            read_zip_file(read_cursor, buffer.get(), read_size);
        }

        // splits it to entries
        std::vector<std::shared_ptr<const central_directory_header>> central_directory;
        size_t dir_size = cd->size_of_the_central_directory;
        size_t count = cd->total_number_of_entries_in_the_central_directory;
        size_t offset = 0;
        central_directory.reserve(count);
        for (size_t i = 0; i < count && offset < dir_size; ++i)
        {
            auto cdh = reinterpret_cast<const central_directory_header*>(buffer.get() + offset);
            if (cdh->central_file_header_signature != central_directory_header::SIGNATURE)
                throw std::runtime_error("unknown file format");
            if (offset + cdh->total_header_size() > dir_size)
                throw std::runtime_error("unknown file format");

            offset += cdh->total_header_size();
            central_directory.emplace_back(buffer, cdh);
        }

        // parses central_directory_headers to file_headers
        std::vector<file_header> central_directory_parsed;
        central_directory_parsed.reserve(count);
        for (const auto& h : central_directory)
            central_directory_parsed.push_back(file_header::from_central_directory_header(h.get()));

        return central_directory_parsed;
    }

    NANONZIP_EXPORT zip_file_reader::zip_file_reader(seek_and_read_file_function zip_file, std::streamoff length) : read_zip_file_(std::move(zip_file))
    {
        if (auto ecd64 = find_end_of_central_directory_record<zip64_end_of_central_directory_record>(read_zip_file_, length))
            this->central_directory_ = read_central_directory<zip64_end_of_central_directory_record>(read_zip_file_, ecd64.get());
        else if (auto ecd = find_end_of_central_directory_record<end_of_central_directory_record>(read_zip_file_, length))
            this->central_directory_ = read_central_directory<end_of_central_directory_record>(read_zip_file_, ecd.get());
        else
            throw std::runtime_error("zip_file_reader: failed to read end_of_central_directory_record");
    }

    static constexpr inline uint32_t crc32_table[] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };

    /// Decrypt stream
    struct zip_file_reader::decrypt_impl
    {
        uint32_t k0_ = 305419896;
        uint32_t k1_ = 591751049;
        uint32_t k2_ = 878082192;

        decrypt_impl(std::string_view password)
        {
            for (char c : password)
                update_keys(c);
        }

        void update_keys(uint8_t c)
        {
            k0_ = crc32_table[static_cast<uint8_t>(k0_ ^ c)] ^ k0_ >> 8;
            k1_ = k1_ + static_cast<uint8_t>(k0_);
            k1_ = k1_ * 134775813 + 1;
            k2_ = crc32_table[static_cast<uint8_t>(k2_ ^ static_cast<uint8_t>(k1_ >> 24))] ^ k2_ >> 8;
        }

        uint8_t process_byte(uint8_t b)
        {
            uint32_t u = k2_ | 2;
            b ^= static_cast<uint8_t>(u * (u ^ 1) >> 8);
            update_keys(b);
            return b;
        }

        void process_buffer(void* buffer, size_t sz)
        {
            auto buf = static_cast<uint8_t*>(buffer);
            for (size_t i = 0; i < sz; ++i)
                buf[i] = process_byte(buf[i]);
        }
    };

    /// Crc32 calculation
    struct zip_file_reader::crc32_impl
    {
        [[nodiscard]] static inline uint32_t crc32(const void* buf, uint32_t size, uint32_t crc = 0)
        {
#ifdef NANONZIP_ENABLE_ZLIB
            return ::crc32(crc, static_cast<const uint8_t*>(buf), size);
#else
            crc = ~crc;
            for (uint32_t i = 0; i < size; ++i)
                crc = crc32_table[static_cast<uint8_t>(crc ^ static_cast<const uint8_t*>(buf)[i])] ^ crc >> 8;
            return ~crc;
#endif
        }
    };

#ifdef NANONZIP_ENABLE_ZLIB
    /// Inflate stream
    struct zip_file_reader::zlib_inflate_impl
    {
        z_stream z_stream_{};
        std::streamoff output_remain_bytes_{};
        std::vector<Byte> input_buffer_{};
        size_t input_buffer_used_{};

        zlib_inflate_impl(std::streamoff output_data_size, ssize32_t buffer_size = 262144)
            : output_remain_bytes_(output_data_size)
            , input_buffer_(buffer_size)
            , input_buffer_used_(input_buffer_.size())
        {
            if (auto r = ::inflateInit2(&z_stream_, -MAX_WBITS); r != Z_OK)
                throw std::runtime_error("zlib::init error");
        }

        zlib_inflate_impl(const zlib_inflate_impl& other) = delete;
        zlib_inflate_impl(zlib_inflate_impl&& other) noexcept = delete;
        zlib_inflate_impl& operator=(const zlib_inflate_impl& other) = delete;
        zlib_inflate_impl& operator=(zlib_inflate_impl&& other) noexcept = delete;
        ~zlib_inflate_impl() { inflateEnd(&z_stream_); }

        template <class read_input_fun = std::function<ssize32_t(void* input_buf, ssize32_t input_len)>,
                  std::enable_if_t<std::is_invocable_r_v<ssize32_t, read_input_fun, void*, ssize32_t>>* = nullptr>
        ssize32_t inflate(void* output_buf, ssize32_t output_len, read_input_fun&& read_input)
        {
            output_len = static_cast<ssize32_t>(std::min<intmax_t>(output_len, output_remain_bytes_));

            z_stream_.next_out = static_cast<::Byte*>(output_buf);
            z_stream_.avail_out = static_cast<uInt>(output_len);
            while (z_stream_.avail_out > 0)
            {
                if (z_stream_.avail_in == 0) // need more input
                {
                    auto input_len = read_input(input_buffer_.data(), static_cast<ssize32_t>(input_buffer_.size()));
                    if (input_len == 0) break;
                    z_stream_.next_in = input_buffer_.data();
                    z_stream_.avail_in = input_len;
                }

                auto result = ::inflate(&z_stream_, Z_SYNC_FLUSH);
                if (result == Z_STREAM_END) break;
                if (result < 0) throw std::runtime_error("zlib::inflate error " + std::to_string(result) + " " + std::string(z_stream_.msg ? z_stream_.msg : ""));
            }

            auto written_bytes = static_cast<ssize32_t>(z_stream_.next_out - static_cast<::Byte*>(output_buf));
            output_remain_bytes_ -= written_bytes;
            return written_bytes;
        }
    };
#endif

#ifdef NANONZIP_ENABLE_BZIP2
    /// bzip2 decompress stream
    struct zip_file_reader::bzip2_decompress_impl
    {
        bz_stream bz_stream_{};
        std::streamoff output_remain_bytes_{};
        std::vector<char> input_buffer_{};
        size_t input_buffer_used_{};

        bzip2_decompress_impl(std::streamoff output_data_size, ssize32_t buffer_size = 262144)
            : output_remain_bytes_(output_data_size)
            , input_buffer_(buffer_size)
            , input_buffer_used_(input_buffer_.size())
        {
            if (auto r = ::BZ2_bzDecompressInit(&bz_stream_, 0, 0); r != BZ_OK)
                throw std::runtime_error("bzlib2::init error");
        }

        bzip2_decompress_impl(const bzip2_decompress_impl& other) = delete;
        bzip2_decompress_impl(bzip2_decompress_impl&& other) noexcept = delete;
        bzip2_decompress_impl& operator=(const bzip2_decompress_impl& other) = delete;
        bzip2_decompress_impl& operator=(bzip2_decompress_impl&& other) noexcept = delete;
        ~bzip2_decompress_impl() { ::BZ2_bzDecompressEnd(&bz_stream_); }

        template <class read_input_fun = std::function<ssize32_t(void* input_buf, ssize32_t input_len)>,
                  std::enable_if_t<std::is_invocable_r_v<ssize32_t, read_input_fun, void*, ssize32_t>>* = nullptr>
        ssize32_t decompress(void* output_buf, ssize32_t output_len, read_input_fun&& read_input)
        {
            output_len = static_cast<ssize32_t>(std::min<intmax_t>(output_len, output_remain_bytes_));

            bz_stream_.next_out = static_cast<char*>(output_buf);
            bz_stream_.avail_out = static_cast<unsigned>(output_len);
            while (bz_stream_.avail_out > 0)
            {
                if (bz_stream_.avail_in == 0) // need more input
                {
                    auto input_len = read_input(input_buffer_.data(), static_cast<ssize32_t>(input_buffer_.size()));
                    if (input_len == 0) break;
                    bz_stream_.next_in = input_buffer_.data();
                    bz_stream_.avail_in = input_len;
                }

                auto result = ::BZ2_bzDecompress(&bz_stream_);
                if (result == BZ_STREAM_END) break;
                if (result < 0) throw std::runtime_error("BZ2_bzDecompress error: " + std::to_string(result));
            }

            auto written_bytes = static_cast<ssize32_t>(bz_stream_.next_out - static_cast<char*>(output_buf));
            output_remain_bytes_ -= written_bytes;
            return written_bytes;
        }
    };
#endif

    NANONZIP_EXPORT file zip_file_reader::open_file_stream(const file_header& file_header, [[maybe_unused]] std::string_view password) const
    {
        const std::streamoff uncompressed_size{file_header.uncompressed_size};
        const std::streamoff compressed_size{file_header.compressed_size};
        std::streamoff cursor{file_header.relative_offset_of_local_header};

        // local file header
        {
            local_file_header fh{};
            read_zip_file_(cursor, &fh, static_cast<ssize32_t>(local_file_header::fixed_header_size()));
            if (fh.local_file_header_signature != local_file_header::SIGNATURE)
                throw std::runtime_error("file corrupted: local file header signature not match.");
            cursor = file_header.relative_offset_of_local_header + static_cast<std::streamoff>(fh.total_header_size());
        }

        // raw reading function
        using read_file_function = std::function<ssize32_t(void* buf, ssize32_t len)>;
        read_file_function read_file = [read_zip_file_ = read_zip_file_, cursor, remain = compressed_size](void* buffer, ssize32_t size) mutable -> ssize32_t
        {
            auto read_size = static_cast<ssize32_t>(std::min<std::streamoff>(size, remain));
            read_zip_file_(cursor, buffer, read_size);
            cursor += read_size;
            remain -= read_size;
            return read_size;
        };

        if (file_header.general_purpose_bit_flag & 1)
        {
            read_file = [lower = std::move(read_file), decrypt = decrypt_impl(password)](void* buffer, ssize32_t size) mutable -> ssize32_t
            {
                ssize32_t r = lower(buffer, size);
                decrypt.process_buffer(buffer, r);
                return r;
            };

            std::byte encryption_header[12]{};
            read_file(encryption_header, 12);
        }

        // decompress file
        switch (file_header.compression_method)
        {
        case compression_method_t::stored: // no compress
            break;

#ifdef NANONZIP_ENABLE_ZLIB
        case compression_method_t::deflate:
            read_file = [lower = std::move(read_file), inflate = std::make_shared<zlib_inflate_impl>(uncompressed_size)](void* buffer, ssize32_t size) mutable -> ssize32_t
            {
                return inflate->inflate(buffer, size, lower);
            };
            break;
#endif

#ifdef NANONZIP_ENABLE_BZIP2
        case compression_method_t::bzip2:
            read_file = [lower = std::move(read_file), bzlib2 = std::make_shared<bzip2_decompress_impl>(uncompressed_size)](void* buffer, ssize32_t size) mutable -> ssize32_t
            {
                return bzlib2->decompress(buffer, size, lower);
            };
            break;
#endif

        default:
            throw std::runtime_error("compression_method " + std::to_string(static_cast<int>(file_header.compression_method)) + " is not supported.");
        }

        // calculates crc32
        read_file = [lower = std::move(read_file), length = uncompressed_size, current_crc32 = uint32_t(), expected = file_header.crc_32](void* buffer, ssize32_t size) mutable -> ssize32_t
        {
            size = lower(buffer, size);
            current_crc32 = crc32_impl::crc32(buffer, static_cast<uint32_t>(size), current_crc32);

            if (length -= size; length == 0)
            {
                if (current_crc32 != expected)
                    throw std::runtime_error("crc32 is not match!");
            }

            return size;
        };

        // divides read calls by 1GiB
        auto file_read_func = [read_file = std::move(read_file)](void* buf, size_t len) -> size_t
        {
            size_t cursor = 0;
            while (cursor < len)
            {
                auto r = read_file(
                    static_cast<std::byte*>(buf) + cursor,
                    static_cast<ssize32_t>(std::min<size_t>(len - cursor, 1073741824))); // 1GiB
                cursor += r;
                if (r == 0) break;
            }
            return cursor;
        };

        return file{file_header, std::move(file_read_func)};
    }
}
