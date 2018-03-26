cmake_minimum_required(VERSION 3.9)
project(shadowsocks)

set(CMAKE_CXX_STANDARD 14)

find_package(Threads REQUIRED)

list(APPEND DEPS
     common_utils
     crypto_utils
     plugin_utils
     protocol_hooks
     ${BOOST_DEPS}
     Threads::Threads
    )

add_subdirectory(server)
add_subdirectory(client)

