cmake_minimum_required(VERSION 3.16)
project(linux_secure_endpoint_agent VERSION 0.1.0 LANGUAGES C CXX)

option(SEA_BUILD_HTTP_FUZZER "Build the Clang libFuzzer target for the pure HTTP request parser" OFF)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
find_package(SQLite3 REQUIRED)

add_executable(sw-agentd agent/src/agent.cpp)
target_include_directories(sw-agentd PRIVATE agent/include)
target_compile_options(sw-agentd PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(sw-agentd PRIVATE OpenSSL::SSL OpenSSL::Crypto SQLite3::SQLite3)

add_executable(sw-server server/src/server.cpp)
target_include_directories(sw-server PRIVATE server/include)
target_compile_options(sw-server PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(sw-server PRIVATE OpenSSL::SSL OpenSSL::Crypto SQLite3::SQLite3)

add_executable(sw-probe transport-c/src/sw_probe.c)
target_compile_options(sw-probe PRIVATE -std=c17 -Wall -Wextra -Wpedantic -Werror)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME sea-inotify-collector COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/collector.py $<TARGET_FILE:sw-agentd>)
    set_tests_properties(sea-inotify-collector PROPERTIES TIMEOUT 60)
    add_test(NAME sea-mtls-policy-smoke
        COMMAND ${CMAKE_COMMAND} -E env BIN_DIR=${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh)
    set_tests_properties(sea-mtls-policy-smoke PROPERTIES TIMEOUT 180)

    add_executable(sea-json-agent-test tests/json_parser_test.cpp)
    target_include_directories(sea-json-agent-test PRIVATE agent/include)
    target_compile_options(sea-json-agent-test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME sea-json-agent-parser COMMAND sea-json-agent-test)

    add_executable(sea-json-server-test tests/json_parser_test.cpp)
    target_include_directories(sea-json-server-test PRIVATE server/include)
    target_compile_options(sea-json-server-test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME sea-json-server-parser COMMAND sea-json-server-test)

    add_executable(sea-http-parser-test tests/http_parser_test.cpp)
    target_include_directories(sea-http-parser-test PRIVATE server/include)
    target_compile_options(sea-http-parser-test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME sea-http-request-parser COMMAND sea-http-parser-test)
endif()

if(SEA_BUILD_HTTP_FUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "SEA_BUILD_HTTP_FUZZER requires Clang with libFuzzer support")
    endif()
    add_executable(sea-http-parser-fuzz tests/http_parser_fuzz.cpp)
    target_include_directories(sea-http-parser-fuzz PRIVATE server/include)
    target_compile_options(sea-http-parser-fuzz PRIVATE -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(sea-http-parser-fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
