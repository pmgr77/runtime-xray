cmake_minimum_required(VERSION 3.16)
project(RuntimeXRayExamples LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_executable(custom_analyzer_demo
    main_demo.cpp
    credit_card_analyzer.cpp
    cloud_credential_analyzer.cpp
    ioc_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/analyzer_registry.cpp
    ${CMAKE_SOURCE_DIR}/src/builtin_analyzers.cpp
)

target_include_directories(custom_analyzer_demo PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)