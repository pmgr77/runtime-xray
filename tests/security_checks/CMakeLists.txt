# tests/security_checks/CMakeLists.txt

enable_language(C)

# Helper to build test binaries from probe.c
function(add_security_test_binary NAME COMPILE_FLAGS LINK_FLAGS)
    add_executable(${NAME} probe.c)
    set_target_properties(${NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
    if(NOT "${COMPILE_FLAGS}" STREQUAL "")
        target_compile_options(${NAME} PRIVATE ${COMPILE_FLAGS})
    endif()
    if(NOT "${LINK_FLAGS}" STREQUAL "")
        target_link_options(${NAME} PRIVATE ${LINK_FLAGS})
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Basic hardening test binaries (probe.c)
# ---------------------------------------------------------------------------

# NX
add_security_test_binary(nx_enabled "" "-Wl,-z,noexecstack")
add_security_test_binary(nx_disabled "" "-Wl,-z,execstack")

# PIE
add_security_test_binary(pie_enabled "-fPIE" "-pie")
add_security_test_binary(pie_disabled "-no-pie" "-no-pie")

# RELRO
add_security_test_binary(relro_full "" "-Wl,-z,relro" "-Wl,-z,now")
add_security_test_binary(relro_partial "" "-Wl,-z,relro" "-Wl,-z,lazy")
add_security_test_binary(relro_disabled "" "-Wl,-z,norelro")

# Canary
add_security_test_binary(canary_enabled   "-fstack-protector-strong" "")
add_security_test_binary(canary_disabled  "-fno-stack-protector"     "")

# ---------------------------------------------------------------------------
# Dangerous API test binary
# ---------------------------------------------------------------------------
add_executable(dangerous_apis dangerous_apis.c)
target_compile_options(dangerous_apis PRIVATE -fno-builtin -O0)
set_target_properties(dangerous_apis PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

# ---------------------------------------------------------------------------
# Existing hardening tests (updated to use $<TARGET_FILE:xray> and --verbose where appropriate)
# ---------------------------------------------------------------------------

add_test(NAME check_nx_enabled COMMAND $<TARGET_FILE:xray> --verbose $<TARGET_FILE:nx_enabled>)
set_tests_properties(check_nx_enabled PROPERTIES PASS_REGULAR_EXPRESSION "NX: Enabled")

add_test(NAME check_nx_disabled COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:nx_disabled>)
set_tests_properties(check_nx_disabled PROPERTIES PASS_REGULAR_EXPRESSION "NX: Disabled")

add_test(NAME check_pie_enabled COMMAND $<TARGET_FILE:xray> --verbose $<TARGET_FILE:pie_enabled>)
set_tests_properties(check_pie_enabled PROPERTIES PASS_REGULAR_EXPRESSION "PIE: Enabled")

add_test(NAME check_pie_disabled COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:pie_disabled>)
set_tests_properties(check_pie_disabled PROPERTIES PASS_REGULAR_EXPRESSION "PIE: Disabled")

add_test(NAME check_relro_full COMMAND $<TARGET_FILE:xray> --verbose $<TARGET_FILE:relro_full>)
set_tests_properties(check_relro_full PROPERTIES PASS_REGULAR_EXPRESSION "RELRO: Full")

add_test(NAME check_relro_partial COMMAND $<TARGET_FILE:xray> --verbose $<TARGET_FILE:relro_partial>)
set_tests_properties(check_relro_partial PROPERTIES PASS_REGULAR_EXPRESSION "RELRO: (Full|Partial)")

add_test(NAME check_relro_disabled COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:relro_disabled>)
set_tests_properties(check_relro_disabled PROPERTIES PASS_REGULAR_EXPRESSION "RELRO: Disabled")

add_test(NAME check_canary_enabled COMMAND $<TARGET_FILE:xray> --verbose $<TARGET_FILE:canary_enabled>)
set_tests_properties(check_canary_enabled PROPERTIES PASS_REGULAR_EXPRESSION "Canary: Enabled")

add_test(NAME check_canary_disabled COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:canary_disabled>)
set_tests_properties(check_canary_disabled PROPERTIES PASS_REGULAR_EXPRESSION "Canary: Disabled")

# ---------------------------------------------------------------------------
# Dangerous API detection tests
# ---------------------------------------------------------------------------

add_test(NAME check_dangerous_apis_unsafe_string
         COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:dangerous_apis>)
set_tests_properties(check_dangerous_apis_unsafe_string PROPERTIES
    PASS_REGULAR_EXPRESSION "Dangerous API: strcpy"
)

add_test(NAME check_dangerous_apis_weak_random
         COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:dangerous_apis>)
set_tests_properties(check_dangerous_apis_weak_random PROPERTIES
    PASS_REGULAR_EXPRESSION "Dangerous API: rand"
)

add_test(NAME check_dangerous_apis_command_exec
         COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:dangerous_apis>)
set_tests_properties(check_dangerous_apis_command_exec PROPERTIES
    PASS_REGULAR_EXPRESSION "Dangerous API: system"
)

add_test(NAME check_dangerous_apis_network
         COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:dangerous_apis>)
set_tests_properties(check_dangerous_apis_network PROPERTIES
    PASS_REGULAR_EXPRESSION "Dangerous API: gethostbyname"
)

# ---------------------------------------------------------------------------
# Severity filtering tests
# ---------------------------------------------------------------------------

# Default (no --verbose) should NOT show Info-level positive checks
add_test(NAME check_default_hides_info
         COMMAND $<TARGET_FILE:xray> $<TARGET_FILE:nx_enabled>)
set_tests_properties(check_default_hides_info PROPERTIES
    FAIL_REGULAR_EXPRESSION "NX: Enabled"
)

# --verbose should show Info-level positive checks
add_test(NAME check_verbose_shows_info
         COMMAND $<TARGET_FILE:xray> --verbose $<TARGET_FILE:nx_enabled>)
set_tests_properties(check_verbose_shows_info PROPERTIES
    PASS_REGULAR_EXPRESSION "NX: Enabled"
)

# --min-severity=High should show High (NX Disabled) but hide Info (Canary Enabled)
add_test(NAME check_min_severity_high
         COMMAND $<TARGET_FILE:xray> --min-severity=High $<TARGET_FILE:nx_disabled>)
set_tests_properties(check_min_severity_high PROPERTIES
    PASS_REGULAR_EXPRESSION "NX: Disabled"
    FAIL_REGULAR_EXPRESSION "Canary: Enabled"
)

# --min-severity=Info should show Info (Canary Enabled)
add_test(NAME check_min_severity_info
         COMMAND $<TARGET_FILE:xray> --min-severity=Info $<TARGET_FILE:canary_enabled>)
set_tests_properties(check_min_severity_info PROPERTIES
    PASS_REGULAR_EXPRESSION "Canary: Enabled"
)