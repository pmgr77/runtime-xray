cmake_minimum_required(VERSION 3.16)
project(RuntimeXRay VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

add_executable(xray
    src/main.cpp
    src/mapped_file.cpp
    src/elf_parser.cpp
)

target_include_directories(xray PRIVATE include)