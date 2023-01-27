/// @file
/// @brief  nanonzip.test.cpp
/// @author (C) 2023 ttsuki
/// MIT License

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <algorithm>

#include <nanonzip.h>

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        std::clog << "pass a zip file path to arg.\n";
        return 1;
    }

    const std::filesystem::path zip_file_path = std::filesystem::u8path(argv[1]);
    const std::string password = argv[2] ? argv[2] : "";

    try
    {
        // zip file
        std::clog << "opening " << zip_file_path.u8string() << "...\n";
        nanonzip::zip_file_reader zip(zip_file_path);

        const auto extract_root = std::filesystem::weakly_canonical(std::filesystem::current_path());

        for (const auto& info : zip.files())
        {
            try
            {
                const auto target_path = std::filesystem::weakly_canonical(extract_root / info.path);

                if (bool target_path_is_outside_of_extract_root = (std::search(target_path.begin(), target_path.end(), extract_root.begin(), extract_root.end()) != target_path.begin()))
                    throw std::runtime_error("target path is out side of extract_root directory.");

                if (info.path.u8string().back() == '/')
                {
                    // directory
                    std::clog << "making directory " << target_path.u8string() << "... ";
                    std::filesystem::create_directories(target_path);
                    std::clog << " created.\n";
                }
                else
                {
                    // file
                    std::clog << "opening file " << info.path.u8string() << "... ";
                    auto file = zip.open_file(info.path, password);

                    std::clog << "\rwriting file " << file.path().u8string() << "... ";
                    std::filesystem::create_directories(target_path.parent_path());
                    std::ofstream out(target_path, std::ios::out | std::ios::binary);

                    std::streamoff total = 0;
                    while (total < file.size())
                    {
                        std::vector<char> buf(1048576); // reading buffer
                        size_t r = file.read(buf.data(), buf.size());
                        out.write(buf.data(), static_cast<std::streamsize>(r));
                        total += static_cast<std::streamsize>(r);
                        std::clog << " \rwriting file " << file.path().u8string() << "... " << total << "/" << file.size() << " bytes written.";
                    }
                    std::clog << "\n";
                }
            }
            catch (const std::runtime_error& e)
            {
                std::clog << e.what() << "\n";
            }
        }

        std::clog << "end.\n";
    }
    catch (const std::runtime_error& e)
    {
        std::clog << e.what() << "\n";
        return 1;
    }

    return 0;
}
