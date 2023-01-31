nano𝒏zip
========

A study for simple unzip program (with optional zlib/bzip2).

for zip files as game application assets bundle.

# features
  - zip64 extension support.
  - basic password encrypted zip file support.
  - crc32 calculation support.
  - store algorithm (= method 0) support.
  - deflate algorithm (= method 8) support (with built-in implementation or zlib).
  - bzip2 compress algorithm (= method 12) support (with bzip2).
  - open zip file from memory (or user defined file-reading function).

## files
  - [`nanonzip.h`](nanonzip.h): public api header
  - [`nanonzip.cpp`](nanonzip.cpp): all implementation
  - [`test/`](test/): 
    - [`test/nanonzip.test.cpp`](test/nanonzip.test.cpp): a sample unzip program

## library look and feel

from [`test/nanonzip.test.cpp`](test/nanonzip.test.cpp)

```cpp

  const std::filesystem::path zip_file_path = std::filesystem::u8path(argv[1]);
  const std::string password = argv[2] ? argv[2] : "";

  // zip file
  nanonzip::zip_file_reader zip(zip_file_path);

  const auto extract_root = std::filesystem::weakly_canonical(std::filesystem::current_path());

  for (const auto& info : zip.files())
  {
    const auto target_path = std::filesystem::weakly_canonical(extract_root / info.path);

    if (bool target_path_is_outside_of_extract_root = /* ... */)
      throw std::runtime_error("target path is out side of extract_root directory.");

    if (info.path.u8string().back() == '/')
    {
      // directory
      std::filesystem::create_directories(target_path);
    }
    else
    {
      // file
      auto file = zip.open_file(info.path, password);

      std::filesystem::create_directories(target_path.parent_path());
      std::ofstream out(target_path, std::ios::out | std::ios::binary);

      std::streamoff total = 0;
      while (total < file.size())
      {
        std::vector<char> buf(1048576);
        size_t r = file.read(buf.data(), buf.size());
        out.write(buf.data(), static_cast<std::streamsize>(r));
        total += static_cast<std::streamsize>(r);
      }
    }
  }

```

# build

## env
  - C++17
  - zlib (optional, for instead of built-in inflate algorithm implementation)
  - bzip2 (optional, to support compression_type=12)

## Visual Studio
  - [`test/nanonzip.test.sln`](test/nanonzip.test.sln) with vcpkg integration
    - `vcpkg install zlib` and `#define NANONZIP_ENABLE_ZLIB` (optional)
    - `vcpkg install bzip2` and `#define NANONZIP_ENABLE_BZIP2` (optional)
  
  * To define macros, [`Directory.Build.props`](test/Directory.Build.props) can be used.  
    [google it: Directory.Build.props](https://www.google.com/search?q=Directory.build.props)

## g++

-  g++-11

    ```sh
    g++ -std=c++17 -I. nanonzip.cpp test/nanonzip.test.cpp 
    ```
    
    or

    ```sh
    g++ -std=c++17 -I. \
      -DNANONZIP_ENABLE_ZLIB -DNANONZIP_ENABLE_BZIP2 \
      nanonzip.cpp test/nanonzip.test.cpp -lz -lbz2
    ```

---

[MIT License](LICENSE) Copyright (c) 2023 ttsuki
