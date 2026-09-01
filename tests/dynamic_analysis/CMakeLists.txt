
enable_language(C)

# Existing dynamic_target (if not already defined elsewhere)
add_executable(dynamic_target dynamic_target.c)
target_compile_options(dynamic_target PRIVATE -O0)

# Fork test
add_executable(fork_test fork_test.c)
target_compile_options(fork_test PRIVATE -O0)

# Thread test binary
add_executable(thread_test thread_test.c)
target_compile_options(thread_test PRIVATE -O0 -pthread)
target_link_libraries(thread_test pthread)

add_executable(exec_echo_test exec_echo_test.c)
target_compile_options(exec_echo_test PRIVATE -O0)

# Optionally, set output directory
set_target_properties(dynamic_target fork_test thread_test exec_echo_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})