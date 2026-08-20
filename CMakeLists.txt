cmake_minimum_required(VERSION 3.16)
project(RuntimeXRay VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

enable_testing()

add_executable(xray
    src/main.cpp
    src/mapped_file.cpp
    src/elf_parser.cpp
)
target_include_directories(xray PRIVATE include)

add_subdirectory(tests/security_checks)

add_executable(xray-trace
    src/main_trace.cpp
    src/tachikoma.cpp
    src/syscall_names.cpp
    src/dynamic_analysis.cpp
)
target_include_directories(xray-trace PRIVATE include)
target_compile_options(xray-trace PRIVATE -Wall -Wextra)
target_compile_definitions(xray-trace PRIVATE _GNU_SOURCE)
add_test(NAME check_xray_trace_smoke
         COMMAND $<TARGET_FILE:xray-trace> --verbose /bin/ls)
set_tests_properties(check_xray_trace_smoke PROPERTIES PASS_REGULAR_EXPRESSION "openat")

# Unit tests for dynamic analysis helpers
add_executable(test_dynamic_helpers tests/dynamic_analysis/test_dynamic_helpers.cpp src/dynamic_analysis.cpp)
target_include_directories(test_dynamic_helpers PRIVATE include)
target_compile_options(test_dynamic_helpers PRIVATE -Wall -Wextra)
add_test(NAME check_dynamic_helpers COMMAND test_dynamic_helpers)

# Dynamic integration test binary
enable_language(C)
add_executable(dynamic_target tests/dynamic_analysis/dynamic_target.c)
set_target_properties(dynamic_target PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests/dynamic_analysis)
target_compile_options(dynamic_target PRIVATE -O0)   # optimization disabled

# Integration tests for xray-trace dynamic findings
add_test(NAME check_dynamic_file_access
         COMMAND $<TARGET_FILE:xray-trace> $<TARGET_FILE:dynamic_target>)
set_tests_properties(check_dynamic_file_access PROPERTIES
    PASS_REGULAR_EXPRESSION "Sensitive file access"
)

add_test(NAME check_dynamic_network
         COMMAND $<TARGET_FILE:xray-trace> $<TARGET_FILE:dynamic_target>)
set_tests_properties(check_dynamic_network PROPERTIES
    PASS_REGULAR_EXPRESSION "Suspicious network connection"
)

add_test(NAME check_dynamic_write_secret
         COMMAND $<TARGET_FILE:xray-trace> $<TARGET_FILE:dynamic_target>)
set_tests_properties(check_dynamic_write_secret PROPERTIES
    PASS_REGULAR_EXPRESSION "Sensitive data written"
)

add_test(NAME check_dynamic_output_scan
         COMMAND $<TARGET_FILE:xray-trace> $<TARGET_FILE:dynamic_target>)
set_tests_properties(check_dynamic_output_scan PROPERTIES
    PASS_REGULAR_EXPRESSION "Sensitive data found in process output"
)