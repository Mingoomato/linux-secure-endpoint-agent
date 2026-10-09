cmake_minimum_required(VERSION 3.16)
project(linux_secure_endpoint_agent VERSION 0.1.0 LANGUAGES C CXX)

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
    add_test(NAME sea-mtls-policy-smoke COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh)
    set_tests_properties(sea-mtls-policy-smoke PROPERTIES TIMEOUT 180)
endif()
