cmake_minimum_required(VERSION 3.16)
project(RuntimeXRay VERSION 0.1.0 LANGUAGES CXX)
option(SKIP_PTRACE_TESTS "Skip ptrace-based dynamic tests (useful for emulated environments)" OFF)
option(BUILD_EXAMPLES "Build custom analyzer examples" OFF)
option(SKIP_EBPF_TESTS "Skip eBPF-based integration tests (useful for CI without eBPF)" OFF)
option(BUILD_EBPF_BACKEND "Build the eBPF tracing backend" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

enable_testing()

include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# ---------------------------------------------------------------------------
# Define source list
# ---------------------------------------------------------------------------
set(RUNTIMEXRAY_SOURCES
    src/main.cpp
    src/common_cli.cpp
    src/commands/analyze_command.cpp
    src/commands/trace_command.cpp
    src/commands/mem_command.cpp
    src/mapped_file.cpp
    src/elf_parser.cpp
    src/tachikoma.cpp
    src/syscall_names.cpp
    src/dynamic_analysis.cpp
    src/memory_scanner.cpp
    src/analyzer_registry.cpp
    src/builtin_analyzers.cpp
    src/finding_filter.cpp
    src/reporter.cpp
    src/ptrace_backend.cpp
    src/logger.cpp
    src/lineage_analyzer.cpp
)

# ---------------------------------------------------------------------------
# eBPF backend (optional)
# ---------------------------------------------------------------------------
if(BUILD_EBPF_BACKEND)
    list(APPEND RUNTIMEXRAY_SOURCES src/ebpf_backend.cpp)

    find_program(CLANG_EXECUTABLE clang REQUIRED)
    find_program(XXD_EXECUTABLE xxd)
    if(NOT XXD_EXECUTABLE)
        find_program(PYTHON3_EXECUTABLE python3 REQUIRED)
    endif()

    find_path(LIBBPF_INCLUDE_DIR bpf/bpf_helpers.h)
    find_library(LIBBPF_LIBRARY bpf)
    find_library(ELF_LIBRARY elf)
    find_library(ZLIB_LIBRARY z)

    if(NOT LIBBPF_INCLUDE_DIR OR NOT LIBBPF_LIBRARY)
        message(FATAL_ERROR "libbpf not found. Install libbpf-dev.")
    endif()

    execute_process(
        COMMAND uname -m
        OUTPUT_VARIABLE MACHINE_ARCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(EBPF_ARCH_INCLUDE "/usr/include/${MACHINE_ARCH}-linux-gnu")

    set(EBPF_SOURCE ${CMAKE_SOURCE_DIR}/ebpf/trace.bpf.c)
    set(EBPF_OBJECT ${CMAKE_BINARY_DIR}/trace.bpf.o)
    set(EBPF_HEADER ${CMAKE_BINARY_DIR}/trace_bpf_bytecode.h)

    add_custom_command(
        OUTPUT ${EBPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf
                -I/usr/include/bpf
                -I${EBPF_ARCH_INCLUDE}
                -c ${EBPF_SOURCE} -o ${EBPF_OBJECT}
        DEPENDS ${EBPF_SOURCE}
        COMMENT "Compiling eBPF program"
    )

    if(XXD_EXECUTABLE)
        add_custom_command(
            OUTPUT ${EBPF_HEADER}
            COMMAND ${XXD_EXECUTABLE} -i -n trace_bpf_bytecode ${EBPF_OBJECT} > ${EBPF_HEADER}
            DEPENDS ${EBPF_OBJECT}
            COMMENT "Generating eBPF bytecode header"
        )
    else()
        add_custom_command(
            OUTPUT ${EBPF_HEADER}
            COMMAND ${PYTHON3_EXECUTABLE} -c
                    "import sys; data = open('${EBPF_OBJECT}', 'rb').read(); print('unsigned char trace_bpf_bytecode[] = {', ', '.join('0x{:02x}'.format(b) for b in data), '};'); print('unsigned int trace_bpf_bytecode_len = {};'.format(len(data)))" > ${EBPF_HEADER}
            DEPENDS ${EBPF_OBJECT}
            COMMENT "Generating eBPF bytecode header using python3"
        )
    endif()

    add_custom_target(ebpf_bytecode DEPENDS ${EBPF_HEADER})
endif()

# ---------------------------------------------------------------------------
# Main executable
# ---------------------------------------------------------------------------
add_executable(runtimexray ${RUNTIMEXRAY_SOURCES})
target_include_directories(runtimexray PRIVATE include)
target_compile_options(runtimexray PRIVATE -Wall -Wextra)
target_compile_definitions(runtimexray PRIVATE _GNU_SOURCE)

if(BUILD_EBPF_BACKEND)
    add_dependencies(runtimexray ebpf_bytecode)
    target_include_directories(runtimexray PRIVATE ${CMAKE_BINARY_DIR})
    target_link_libraries(runtimexray PRIVATE
        ${LIBBPF_LIBRARY}
        ${ELF_LIBRARY}
        ${ZLIB_LIBRARY}
    )
    target_compile_definitions(runtimexray PRIVATE BUILD_EBPF_BACKEND=1)
endif()

target_link_libraries(runtimexray PRIVATE nlohmann_json::nlohmann_json)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# CLI-level mem test
add_test(NAME check_cli_mem_finds_cmdline_secret
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/memory_scanner/test_mem_cli.sh $<TARGET_FILE:runtimexray>)

# Memory scanner unit tests
add_executable(test_memory_scanner
    tests/memory_scanner/test_memory_scanner.cpp
    src/analyzer_registry.cpp
    src/builtin_analyzers.cpp
    src/dynamic_analysis.cpp
)
target_include_directories(test_memory_scanner PRIVATE include)
target_compile_options(test_memory_scanner PRIVATE -Wall -Wextra)
add_test(NAME check_memory_scanner COMMAND $<TARGET_FILE:test_memory_scanner>)

add_subdirectory(tests/security_checks)
add_subdirectory(tests/dynamic_analysis)

# Dynamic helpers tests
add_executable(test_dynamic_helpers
    tests/dynamic_analysis/test_dynamic_helpers.cpp
    src/dynamic_analysis.cpp
)
target_include_directories(test_dynamic_helpers PRIVATE include)
target_compile_options(test_dynamic_helpers PRIVATE -Wall -Wextra)
add_test(NAME check_dynamic_helpers COMMAND $<TARGET_FILE:test_dynamic_helpers>)

# Analyzer registry tests
add_executable(test_analyzer_registry
    tests/analyzer_registry/test_analyzer_registry.cpp
    src/analyzer_registry.cpp
    src/builtin_analyzers.cpp
)
target_include_directories(test_analyzer_registry PRIVATE include)
target_compile_options(test_analyzer_registry PRIVATE -Wall -Wextra)
add_test(NAME check_analyzer_registry COMMAND test_analyzer_registry)

# JSON validation for analyze
add_test(NAME check_json_analyze
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_validation.py
                 analyze $<TARGET_FILE:runtimexray> analyze $<TARGET_FILE:nx_enabled>)

# eBPF tests (only if enabled and not skipped)
if(NOT SKIP_EBPF_TESTS AND BUILD_EBPF_BACKEND)
    add_test(NAME check_ebpf_trace_smoke
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_smoke.sh $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_trace_smoke PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_ebpf_json_verbose
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_json_verbose.sh $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_json_verbose PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    add_test(NAME check_ebpf_timeout
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_timeout.sh $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_timeout PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_ebpf_empty_json
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_empty_json.sh $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_empty_json PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    # eBPF fork/thread tests
    add_test(NAME check_ebpf_follow_forks
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_follow_forks.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:fork_test>)
    set_tests_properties(check_ebpf_follow_forks PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    add_test(NAME check_ebpf_no_follow_forks
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_no_follow_forks.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:fork_test>)
    set_tests_properties(check_ebpf_no_follow_forks PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    add_test(NAME check_ebpf_threads
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_threads.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:thread_test>)
    set_tests_properties(check_ebpf_threads PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 20)    
endif()

if(NOT SKIP_PTRACE_TESTS)
    # JSON validation for trace
    add_test(NAME check_json_trace
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_validation.py
                     trace $<TARGET_FILE:runtimexray> trace --timeout 1 /bin/ls)

    # JSON validation for mem
    add_test(NAME check_json_mem
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_validation_mem.py $<TARGET_FILE:runtimexray>)

    # Self memory scanner integration test
    add_executable(test_memory_scanner_self
        tests/memory_scanner/test_memory_scanner_self.cpp
        src/memory_scanner.cpp
        src/analyzer_registry.cpp
        src/builtin_analyzers.cpp
        src/dynamic_analysis.cpp
    )
    target_include_directories(test_memory_scanner_self PRIVATE include)
    target_compile_options(test_memory_scanner_self PRIVATE -Wall -Wextra)
    add_test(NAME check_memory_scanner_self
             COMMAND $<TARGET_FILE:test_memory_scanner_self> password=cmdline_secret_test)
    set_tests_properties(check_memory_scanner_self PROPERTIES
        ENVIRONMENT "TEST_SECRET=password=env_secret_test")

    add_test(NAME check_xray_trace_smoke
             COMMAND $<TARGET_FILE:runtimexray> trace /bin/ls)
    set_tests_properties(check_xray_trace_smoke PROPERTIES PASS_REGULAR_EXPRESSION "Command: trace")

    add_test(NAME check_dynamic_file_access
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_file_access PROPERTIES PASS_REGULAR_EXPRESSION "Sensitive file access")

    add_test(NAME check_dynamic_network
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_network PROPERTIES PASS_REGULAR_EXPRESSION "Suspicious network connection")

    add_test(NAME check_dynamic_write_secret
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_write_secret PROPERTIES PASS_REGULAR_EXPRESSION "Sensitive data found in memory")

    add_test(NAME check_dynamic_output_scan
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_output_scan PROPERTIES PASS_REGULAR_EXPRESSION "Sensitive data found in memory")

    add_test(NAME check_trace_timeout
             COMMAND $<TARGET_FILE:runtimexray> trace --timeout 1 /bin/sleep 10)
    set_tests_properties(check_trace_timeout PROPERTIES PASS_REGULAR_EXPRESSION "Timed out: yes")

    add_test(NAME check_trace_critical_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity Critical $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_critical_show PROPERTIES PASS_REGULAR_EXPRESSION "Path: /etc/sudoers")

    add_test(NAME check_trace_high_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity High $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_high_show PROPERTIES PASS_REGULAR_EXPRESSION "Path: /tmp/fake_secret_file")

    add_test(NAME check_trace_medium_show
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_medium_show PROPERTIES PASS_REGULAR_EXPRESSION "Path: /etc/passwd")

    add_test(NAME check_trace_low_hide_default
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_low_hide_default PROPERTIES FAIL_REGULAR_EXPRESSION "Path: /etc/hosts")

    add_test(NAME check_trace_low_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity Low $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_low_show PROPERTIES PASS_REGULAR_EXPRESSION "Path: /etc/hosts")

    add_test(NAME check_trace_info_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity Info $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_info_show PROPERTIES PASS_REGULAR_EXPRESSION "Path: /etc/hostname")

    # Fork/thread tracing tests (ptrace)
    add_test(NAME check_trace_follow_forks
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_follow_forks.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:fork_test>)
    set_tests_properties(check_trace_follow_forks PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_trace_no_follow_forks
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_no_follow_forks.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:fork_test>)
    set_tests_properties(check_trace_no_follow_forks PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    # Thread test
    add_test(NAME check_trace_threads
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_threads.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:thread_test>)
    set_tests_properties(check_trace_threads PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples/custom_analyzers)
endif()