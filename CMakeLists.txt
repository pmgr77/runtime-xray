cmake_minimum_required(VERSION 3.16)
project(RuntimeXRay VERSION 0.1.0 LANGUAGES CXX)
option(SKIP_PTRACE_TESTS "Skip ptrace-based dynamic tests (useful for emulated environments)" OFF)
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
    src/memory_reader.cpp
    src/memory_scanner.cpp
    src/url_credential_extractor.cpp
    src/memory_region_policy.cpp
    src/memory_scan_coordinator.cpp
    src/finding_filter.cpp
    src/reporter.cpp
    src/finding_reporter.cpp
    src/ptrace_backend.cpp
    src/logger.cpp
    src/lineage_analyzer.cpp
    src/inherited_fd_discovery.cpp
    src/secret_fingerprinter.cpp
    src/narrative.cpp
    src/narrative_builder.cpp
    src/detection_rule_registry.cpp
    src/detection_engine.cpp
    src/sensitive_file_access_rule.cpp
    src/register_builtin_detection_rules.cpp
    src/secret_extractor.cpp
    src/netrc_extractor.cpp
    src/curl_config_extractor.cpp
    src/sensitive_data_presence_rule.cpp
    src/hardening_rule.cpp
    src/dangerous_api_rule.cpp
    src/network_rule.cpp
    src/sensitive_data_flow_rule.cpp
    src/sensitive_value_cross_process_pipe_chain_rule.cpp
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

    if(MACHINE_ARCH STREQUAL "x86_64")
        set(EBPF_TARGET_ARCH_FLAG "-D__TARGET_ARCH_x86")
    elseif(MACHINE_ARCH STREQUAL "aarch64")
        set(EBPF_TARGET_ARCH_FLAG "-D__TARGET_ARCH_arm64")
    else()
        message(FATAL_ERROR "Unsupported eBPF target arch: ${MACHINE_ARCH}")
    endif()

    add_custom_command(
        OUTPUT ${EBPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf
                ${EBPF_TARGET_ARCH_FLAG}
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

find_package(OpenSSL REQUIRED)
target_link_libraries(runtimexray PRIVATE OpenSSL::Crypto)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# CLI-level mem test
add_test(NAME check_cli_mem_finds_cmdline_secret
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/memory_scanner/test_mem_cli.sh $<TARGET_FILE:runtimexray>)

add_test(NAME check_cli_mem_show_secrets
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/memory_scanner/test_mem_show_secrets.sh $<TARGET_FILE:runtimexray>)

# SecretFingerprinter unit test
add_executable(test_secret_fingerprinter
    tests/unit/test_secret_fingerprinter.cpp
    src/secret_fingerprinter.cpp
)
target_link_libraries(test_secret_fingerprinter PRIVATE OpenSSL::Crypto)
target_include_directories(test_secret_fingerprinter PRIVATE include)
add_test(NAME check_secret_fingerprinter COMMAND $<TARGET_FILE:test_secret_fingerprinter>)

# .netrc extractor unit tests
add_executable(test_netrc_extractor
    tests/unit/test_netrc_extractor.cpp
    src/netrc_extractor.cpp
)
target_include_directories(test_netrc_extractor PRIVATE include)
target_compile_options(test_netrc_extractor PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME check_netrc_extractor COMMAND $<TARGET_FILE:test_netrc_extractor>)

# Curl configuration extractor unit tests
add_executable(test_curl_config_extractor
    tests/unit/test_curl_config_extractor.cpp
    src/curl_config_extractor.cpp
)
target_include_directories(test_curl_config_extractor PRIVATE include)
target_compile_options(test_curl_config_extractor PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME check_curl_config_extractor COMMAND $<TARGET_FILE:test_curl_config_extractor>)

# HTTP(S) URL credential extractor unit tests
add_executable(test_url_credential_extractor
    tests/unit/test_url_credential_extractor.cpp
    src/url_credential_extractor.cpp
)
target_include_directories(test_url_credential_extractor PRIVATE include)
target_compile_options(test_url_credential_extractor PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME check_url_credential_extractor COMMAND $<TARGET_FILE:test_url_credential_extractor>)

add_executable(test_narrative_sessions
    tests/unit/test_narrative_sessions.cpp
    src/narrative.cpp
)
target_include_directories(test_narrative_sessions PRIVATE include)
add_test(NAME check_narrative_sessions COMMAND test_narrative_sessions)

add_executable(test_narrative_builder
    tests/unit/test_narrative_builder.cpp
    src/narrative.cpp
    src/narrative_builder.cpp
)
target_include_directories(test_narrative_builder PRIVATE include)
add_test(NAME check_narrative_builder COMMAND test_narrative_builder)

add_executable(test_reporter_json
    tests/unit/test_reporter_json.cpp
    src/reporter.cpp
)
target_include_directories(test_reporter_json PRIVATE include)
target_link_libraries(test_reporter_json PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME check_reporter_json COMMAND test_reporter_json)

# CLI-level mem lineage test
add_test(NAME check_mem_lineage
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_mem_lineage.sh $<TARGET_FILE:runtimexray>)
set_tests_properties(check_mem_lineage PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 20)

# Memory scanner unit tests
add_executable(test_memory_scanner
    tests/memory_scanner/test_memory_scanner.cpp
    src/secret_extractor.cpp
    src/netrc_extractor.cpp
    src/curl_config_extractor.cpp
    src/secret_fingerprinter.cpp
    src/logger.cpp
)
target_include_directories(test_memory_scanner PRIVATE include)
target_compile_options(test_memory_scanner PRIVATE -Wall -Wextra)
target_link_libraries(test_memory_scanner PRIVATE OpenSSL::Crypto)
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

# JSON validation for analyze
add_test(NAME check_json_analyze
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_validation.py
                 analyze $<TARGET_FILE:runtimexray> analyze $<TARGET_FILE:nx_enabled>)

# Mem JSON/integration tests do not depend on ptrace.
add_test(NAME check_json_mem
         COMMAND ${Python3_EXECUTABLE}
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_validation_mem.py
         $<TARGET_FILE:runtimexray>)

add_executable(test_memory_scanner_self
    tests/memory_scanner/test_memory_scanner_self.cpp
    src/memory_reader.cpp
    src/memory_scanner.cpp
    src/url_credential_extractor.cpp
    src/memory_region_policy.cpp
    src/secret_extractor.cpp
    src/netrc_extractor.cpp
    src/curl_config_extractor.cpp
    src/dynamic_analysis.cpp
    src/logger.cpp
    src/secret_fingerprinter.cpp
)
target_include_directories(test_memory_scanner_self PRIVATE include)
target_compile_options(test_memory_scanner_self PRIVATE -Wall -Wextra)
target_link_libraries(test_memory_scanner_self PRIVATE OpenSSL::Crypto)
add_test(NAME check_memory_scanner_self
         COMMAND $<TARGET_FILE:test_memory_scanner_self> password=cmdline_secret_test)
set_tests_properties(check_memory_scanner_self PROPERTIES
    ENVIRONMENT "TEST_SECRET=password=env_secret_test")

# Memory region parsing and prioritization tests
add_executable(test_memory_region_priority
    tests/unit/test_memory_region_priority.cpp
    src/memory_region_policy.cpp
)

target_include_directories(test_memory_region_priority PRIVATE include)
target_compile_options(test_memory_region_priority PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
add_test(NAME check_memory_region_priority
        COMMAND $<TARGET_FILE:test_memory_region_priority>
)

# ---------------------------------------------------------------------------
# Memory scan coordinator unit tests
#
# Validate event-driven scan authorization, process-image isolation,
# scan-count limits, page reservations, and budget refunds.
#
# These tests exercise coordinator policy and accounting only.
# They do not require ptrace, process memory access, or root privileges.
# ---------------------------------------------------------------------------
add_executable(test_memory_scan_coordinator
    tests/unit/test_memory_scan_coordinator.cpp
    src/memory_scan_coordinator.cpp
)
target_include_directories(test_memory_scan_coordinator PRIVATE include)
target_compile_options(test_memory_scan_coordinator PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)
add_test(NAME check_memory_scan_coordinator COMMAND $<TARGET_FILE:test_memory_scan_coordinator>)

# ---------------------------------------------------------------------------
# Process-image identity and lifecycle unit tests
#
# Verify that LineageAnalyzer exposes stable process-image identities
# across syscall observations, exec transitions, thread activity,
# process termination, and simulated Linux PID reuse.
#
# Tests use synthetic trace events and require neither ptrace privileges
# nor real child processes.
# ---------------------------------------------------------------------------
add_executable(test_process_image_identity
    tests/unit/test_process_image_identity.cpp
    src/lineage_analyzer.cpp
    src/inherited_fd_discovery.cpp
    src/syscall_names.cpp
    src/logger.cpp
)
target_include_directories(test_process_image_identity PRIVATE include)
target_compile_options(test_process_image_identity PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)
add_test(NAME check_process_image_identity COMMAND $<TARGET_FILE:test_process_image_identity>)


# ---------------------------------------------------------------------------
# Inherited FD discovery tests
#
# Creates a real pipe, forks a child and inspects its inherited FDs
# through /proc/<pid>/fd and /proc/<pid>/fdinfo.
#
# Does not require ptrace or root privileges.
# ---------------------------------------------------------------------------
add_executable(test_inherited_fd_discovery
    tests/unit/test_inherited_fd_discovery.cpp
    src/inherited_fd_discovery.cpp
)
target_include_directories(test_inherited_fd_discovery PRIVATE include)
target_compile_options(test_inherited_fd_discovery PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)
add_test(NAME check_inherited_fd_discovery COMMAND $<TARGET_FILE:test_inherited_fd_discovery>)
set_tests_properties(check_inherited_fd_discovery PROPERTIES TIMEOUT 15)

# ---------------------------------------------------------------------------
# FD identity reconciliation across fork / late TaskCreate.
#
# Tests:
#   - Normal TaskCreate ordering
#   - Child observed before TaskCreate
#   - FD replacement without false resource merging
#
# Uses real Linux pipes and fork(), with synthetic event ordering.
# No ptrace privileges required.
# ---------------------------------------------------------------------------
add_executable(test_lineage_fd_discovery_order
    tests/unit/test_lineage_fd_discovery_order.cpp
    src/lineage_analyzer.cpp
    src/inherited_fd_discovery.cpp
    src/syscall_names.cpp
    src/logger.cpp
)
target_include_directories(test_lineage_fd_discovery_order PRIVATE include)
target_compile_options(test_lineage_fd_discovery_order PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
)
add_test(NAME check_lineage_fd_discovery_order COMMAND $<TARGET_FILE:test_lineage_fd_discovery_order>)
set_tests_properties(check_lineage_fd_discovery_order PROPERTIES TIMEOUT 15)

# eBPF tests (only if enabled and not skipped)
if(NOT SKIP_EBPF_TESTS AND BUILD_EBPF_BACKEND)
    add_test(NAME check_ebpf_trace_smoke
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_smoke.sh
            $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_trace_smoke PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_ebpf_json_verbose
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_json_verbose.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_ebpf_json_verbose PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 25)

    add_test(NAME check_ebpf_timeout
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_timeout.sh
            $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_timeout PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_ebpf_empty_json
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_empty_json.sh
            $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_ebpf_empty_json PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    # eBPF fork/thread tests
    add_test(NAME check_ebpf_follow_forks
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_follow_forks.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fork_test>)
    set_tests_properties(check_ebpf_follow_forks PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    add_test(NAME check_ebpf_no_follow_forks
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_no_follow_forks.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fork_test>)
    set_tests_properties(check_ebpf_no_follow_forks PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    add_test(NAME check_ebpf_threads
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_threads.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:thread_test>)
    set_tests_properties(check_ebpf_threads PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 20)

    add_test(NAME check_ebpf_sensitive_object_flow
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_sensitive_object_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:sensitive_object_flow>)
    set_tests_properties(check_ebpf_sensitive_object_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_trace_file_access_outcomes_ebpf
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_trace_file_access_outcomes.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:file_access_outcomes>
            ebpf)
    set_tests_properties(check_trace_file_access_outcomes_ebpf PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 125)

    add_test(NAME check_ebpf_pipe_flow
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ebpf_pipe_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:pipe_flow>)
    set_tests_properties(check_ebpf_pipe_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 20)

    add_test(NAME check_ebpf_sensitive_pipe_chain_env
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_sensitive_pipe_chain_env.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:sensitive_pipe_chain_env>
            ebpf)
    set_tests_properties(check_ebpf_sensitive_pipe_chain_env PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ebpf_fd_exec_inheritance
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fd_exec_inheritance.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fd_exec_inheritance>
            ebpf)
    set_tests_properties(check_ebpf_fd_exec_inheritance PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ebpf_fd_alias_flow
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fd_alias_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fd_alias_flow>
            ebpf)
    set_tests_properties(check_ebpf_fd_alias_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ebpf_fork_dup_exec_flow
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fork_dup_exec_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fork_dup_exec_parent>
            $<TARGET_FILE:fork_dup_exec_helper>
            ebpf
    )
    set_tests_properties(check_ebpf_fork_dup_exec_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ebpf_vfork_dup_exec_flow
            COMMAND sh
            ${CMAKE_SOURCE_DIR}/tests/test_vfork_dup_exec_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:vfork_dup_exec_parent>
            $<TARGET_FILE:fork_dup_exec_helper>
            ebpf
    )
    set_tests_properties(check_ebpf_vfork_dup_exec_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ebpf_cloexec_exec_flow
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cloexec_exec_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:cloexec_exec_flow>
            ebpf
    )
    set_tests_properties(check_ebpf_cloexec_exec_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

endif()

if(NOT SKIP_PTRACE_TESTS)
    # JSON validation for trace
    add_test(NAME check_json_trace
            COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/json_validation.py
            trace $<TARGET_FILE:runtimexray> trace --timeout 1 /bin/ls)

    add_test(NAME check_xray_trace_smoke
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_trace_smoke.sh
             $<TARGET_FILE:runtimexray>)
    set_tests_properties(check_xray_trace_smoke PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_dynamic_file_access
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_file_access PROPERTIES PASS_REGULAR_EXPRESSION "Sensitive file access")

    add_test(NAME check_dynamic_network
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_network PROPERTIES PASS_REGULAR_EXPRESSION "Suspicious network connection")

    add_test(NAME check_dynamic_write_secret
             COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_trace_secret_write.sh
             $<TARGET_FILE:runtimexray>
             $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_dynamic_write_secret PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    add_test(NAME check_trace_timeout
             COMMAND $<TARGET_FILE:runtimexray> trace --timeout 1 /bin/sleep 10)
    set_tests_properties(check_trace_timeout PROPERTIES PASS_REGULAR_EXPRESSION "Timed out: yes")

    add_test(NAME check_trace_critical_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity Critical $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_critical_show PROPERTIES PASS_REGULAR_EXPRESSION "path: /etc/sudoers")

    add_test(NAME check_trace_high_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity High $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_high_show PROPERTIES PASS_REGULAR_EXPRESSION "path: /tmp/fake_secret_file")

    add_test(NAME check_trace_medium_show
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_medium_show PROPERTIES PASS_REGULAR_EXPRESSION "path: /etc/passwd")

    add_test(NAME check_trace_low_hide_default
             COMMAND $<TARGET_FILE:runtimexray> trace $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_low_hide_default PROPERTIES
        PASS_REGULAR_EXPRESSION "path: /etc/passwd"
        FAIL_REGULAR_EXPRESSION "path: /etc/hosts")

    add_test(NAME check_trace_low_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity Low $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_low_show PROPERTIES PASS_REGULAR_EXPRESSION "path: /etc/hosts")

    add_test(NAME check_trace_info_show
             COMMAND $<TARGET_FILE:runtimexray> trace --min-severity Info $<TARGET_FILE:dynamic_target>)
    set_tests_properties(check_trace_info_show PROPERTIES PASS_REGULAR_EXPRESSION "path: /etc/hostname")

    add_test(NAME check_ptrace_sensitive_object_flow
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ptrace_sensitive_object_flow.sh
             $<TARGET_FILE:runtimexray>
             $<TARGET_FILE:sensitive_object_flow>)
    set_tests_properties(check_ptrace_sensitive_object_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ptrace_pipe_flow
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ptrace_pipe_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:pipe_flow>)
    set_tests_properties(check_ptrace_pipe_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 20)

    add_test(NAME check_ptrace_fd_exec_inheritance
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fd_exec_inheritance.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fd_exec_inheritance>
            ptrace
    )
    set_tests_properties(check_ptrace_fd_exec_inheritance PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ptrace_sensitive_pipe_chain_env
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_sensitive_pipe_chain_env.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:sensitive_pipe_chain_env>
            ptrace)
    set_tests_properties(check_ptrace_sensitive_pipe_chain_env PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_process_instance_lifetime
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_process_instance_lifetime.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:thread_lifecycle_test>)
    set_tests_properties(check_process_instance_lifetime PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 15)

    # -----------------------------------------------------------------------
    # C1: Event-driven memory scanning integration regression
    #
    # Runs curl against a local Basic-auth-protected Docker registry.
    # Verifies two independently authorized memory scans and matching
    # read/sendto/memory evidence in the lineage graph.
    #
    # The script generates disposable credentials and validates actual
    # observed_at and observed_in edge endpoints.
    #
    # Return code 125 indicates a missing external fixture, insufficient
    # privileges, or an unavailable test dependency.
    #
    # The test may be slower than ordinary ptrace tests because it
    # performs two bounded scans of live process memory.
    # -----------------------------------------------------------------------
    add_test(NAME check_c1_memory_scan_coordinator
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_c1_memory_scan_coordinator.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_c1_memory_scan_coordinator PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

    # -----------------------------------------------------------------------
    # Stage B1: curl config credential-source regression
    #
    # Verifies that a password loaded through curl --config is observed
    # in the file read, process memory, and outgoing sendto payload.
    #
    # Requires the same local Basic-auth registry fixture as C1.
    # Return code 125 indicates that the test environment is unavailable.
    # -----------------------------------------------------------------------
    add_test(NAME check_b1_curl_config
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_b1_curl_config.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_b1_curl_config PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

    # -----------------------------------------------------------------------
    # Stage D1: HTTP Basic Authorization header regression
    #
    # Verifies Base64-decoded credential correlation across cmdline,
    # process memory, and sendto_data, including evidence edges
    # and plaintext redaction.
    #
    # Requires the local Basic-auth registry fixture.
    # Return code 125 indicates an unavailable test environment.
    # -----------------------------------------------------------------------
    add_test(NAME check_d1_authorization_header
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_d1_authorization_header.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_d1_authorization_header PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

    # -----------------------------------------------------------------------
    # Stage E1: HTTP URL userinfo credential regression
    #
    # Verifies credential detection in cmdline, memory, and sendto_data,
    # matching fingerprints, lineage evidence, and plaintext redaction.
    #
    # Requires a local Basic-auth registry.
    # Return code 125 means the fixture is unavailable.
    # -----------------------------------------------------------------------
    add_test(NAME check_e1_url_credentials
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_e1_url_credentials.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_e1_url_credentials PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

    # -----------------------------------------------------------------------
    # Stage F1: credentials supplied through stdin pipe
    #
    # Verifies read(fd=0), matching fingerprints across read,
    # memory and sendto_data, lineage evidence and plaintext redaction.
    #
    # Inherited stdin may have no resource_id.
    # Return code 125 indicates an unavailable test environment.
    # -----------------------------------------------------------------------
    add_test(NAME check_f1_stdin_credentials
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_f1_stdin_credentials.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_f1_stdin_credentials PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

    # ---------------------------------------------------------------------------
    # F2: Pre-existing pipe inherited on fd=3.
    #
    # The pipe is created outside the traced process.
    # Verify that RuntimeXRay discovers its resource identity and
    # preserves the read role without inventing causal relationships.
    #
    # Does not require the Docker Registry fixture.
    # ---------------------------------------------------------------------------
    add_test(NAME check_f2_inherited_fd3
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_f2_inherited_fd3.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_f2_inherited_fd3 PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

        # ---------------------------------------------------------------------------
        # F3: Pre-existing inherited pipe -> cross-process DataFlow -> TCP.
        #
        # The Python launcher creates the pipe before RuntimeXRay starts.
        # The traced parent writes a synthetic credential to the pipe.
        # The traced child reads and forwards it to a local TCP receiver.
        #
        # Verifies:
        #   - Shared pipe resource identity across processes
        #   - Matching write/read/sendto fingerprints
        #   - Explicit write -> read DataFlow edge
        #   - Exact TCP delivery
        #   - Credential redaction in JSON and text reports
        #
        # No Docker fixture or external network required.
        # ---------------------------------------------------------------------------
        add_test(
                NAME check_f3_inherited_pipe_network
                COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/inherited_pipe_network_lab.py
                $<TARGET_FILE:runtimexray>
        )

        set_tests_properties(check_f3_inherited_pipe_network PROPERTIES TIMEOUT 210 )

    # -----------------------------------------------------------------------
    # Stage C: Fork/COW inherited-secret InitialInspection regression
    #
    # Verifies that a child retaining a private inherited secret
    # is inspected independently of the parent process image.
    #
    # The child does not read or send the secret. Detection must
    # therefore come from InitialInspection rather than I/O events.
    #
    # The script builds a disposable C fixture and verifies the
    # child process identity, memory evidence, and observed_in edge.
    # -----------------------------------------------------------------------
    add_test(NAME check_fork_cow_initial_inspection
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fork_cow_initial_inspection.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_fork_cow_initial_inspection PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 120)

    # -----------------------------------------------------------------------
    # Stage C.2: Memory inspection across exec transitions
    #
    # Verify that failed execve preserves the current executable image,
    # while successful execve advances the executable generation.
    #
    # Both generations must receive independent InitialInspection scans.
    # Secret observations must remain attributed to the correct image,
    # without carrying stale memory evidence across successful exec.
    # -----------------------------------------------------------------------
    add_test(NAME check_exec_memory_transition
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_exec_memory_transition.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_exec_memory_transition PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 120)

    # -----------------------------------------------------------------------
    # Stage C.3: Fork/COW memory mutation and lineage regression
    #
    # Verify independent process images and memory evidence for two
    # forked children under parent-first and child-first COW mutations.
    #
    # The fixture validates byte-level COW isolation. Physical PFN
    # assertions are disabled during RuntimeXRay memory inspection,
    # because remote memory scanning may alter COW page topology.
    #
    # RuntimeXRay must attribute observations to the correct process
    # and must not invent DataFlow edges from memory fingerprint matches.
    # -----------------------------------------------------------------------
    add_test(NAME check_fork_cow_mutation_lineage
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fork_cow_mutation_lineage.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_fork_cow_mutation_lineage PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 150)

    # -----------------------------------------------------------------------
    # Stage D: Differential COW behavior of remote memory readers
    #
    # Negative control:
    #   process_vm_readv is expected to trigger early COW unsharing.
    #
    # Positive control:
    #   /proc/<pid>/mem must preserve shared PFNs until application write.
    #
    # Requires access to physical PFNs through /proc/<pid>/pagemap.
    # Return code 125 means the environment cannot perform the test.
    # -----------------------------------------------------------------------
    add_test(NAME check_memory_reader_cow_differential
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_memory_reader_cow_differential.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_memory_reader_cow_differential PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 180)

    # Stage D.2: Semantic evidence parity between memory readers
    add_test(NAME check_memory_reader_evidence_parity
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_memory_reader_evidence_parity.sh
            $<TARGET_FILE:runtimexray>
    )
    set_tests_properties(check_memory_reader_evidence_parity PROPERTIES TIMEOUT 180)

    add_test(NAME check_ptrace_fd_alias_flow
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fd_alias_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fd_alias_flow>
            ptrace)
    set_tests_properties(check_ptrace_fd_alias_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ptrace_fork_dup_exec_flow
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_fork_dup_exec_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:fork_dup_exec_parent>
            $<TARGET_FILE:fork_dup_exec_helper>
            ptrace)
    set_tests_properties(check_ptrace_fork_dup_exec_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ptrace_vfork_dup_exec_flow
            COMMAND sh
            ${CMAKE_SOURCE_DIR}/tests/test_vfork_dup_exec_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:vfork_dup_exec_parent>
            $<TARGET_FILE:fork_dup_exec_helper>
            ptrace)
    set_tests_properties(check_ptrace_vfork_dup_exec_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

    add_test(NAME check_ptrace_cloexec_exec_flow
            COMMAND sh
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cloexec_exec_flow.sh
            $<TARGET_FILE:runtimexray>
            $<TARGET_FILE:cloexec_exec_flow>
            ptrace
    )
    set_tests_properties(check_ptrace_cloexec_exec_flow PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

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

    add_test(
        NAME check_trace_file_access_outcomes_ptrace
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_trace_file_access_outcomes.sh
                $<TARGET_FILE:runtimexray>
                $<TARGET_FILE:file_access_outcomes>
                ptrace)

    set_tests_properties(
        check_trace_file_access_outcomes_ptrace
        PROPERTIES
            TIMEOUT 30
            SKIP_RETURN_CODE 125)

    add_test(NAME check_capture_program_name
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_capture_program_name.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:exec_echo_test>)
    set_tests_properties(check_capture_program_name PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 10)

    add_test(NAME check_cross_boundary_evidence
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cross_boundary.sh $<TARGET_FILE:runtimexray> $<TARGET_FILE:cross_boundary_test>)
    set_tests_properties(check_cross_boundary_evidence PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 30)

endif()

# ---------------------------------------------------------------------------
# Stage D.3: Memory reader lifecycle regression
#
# Tests munmap/remap, mprotect, concurrent VMA changes, execve and process exit
# for both process_vm_readv and /proc/<pid>/mem.
# ---------------------------------------------------------------------------
add_executable(test_memory_reader_lifecycle
    tests/test_memory_reader_lifecycle.cpp
    src/memory_reader.cpp
)
target_include_directories(test_memory_reader_lifecycle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_test(NAME check_memory_reader_lifecycle COMMAND $<TARGET_FILE:test_memory_reader_lifecycle>)
set_tests_properties(check_memory_reader_lifecycle PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 125)


# Stage D.5: Unified memory reader CLI configuration.
#
# Verify default and explicit reader selection for both trace and mem.
# strace checks the actual kernel syscalls, not just CLI parsing.
# Exit code 125 means the environment cannot perform the test.
add_test(NAME check_memory_reader_cli
        COMMAND sh
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_memory_reader_cli.sh
        $<TARGET_FILE:runtimexray>
)
set_tests_properties(check_memory_reader_cli PROPERTIES SKIP_RETURN_CODE 125 TIMEOUT 180)
