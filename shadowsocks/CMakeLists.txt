cmake_minimum_required(VERSION 3.9)
project(shadowsocks)

set(CMAKE_CXX_STANDARD 14)

find_package(Threads REQUIRED)

list(APPEND BOOST_DEPS
     boost_log-mt
     boost_thread-mt
     boost_program_options-mt
     boost_system-mt
    )

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

