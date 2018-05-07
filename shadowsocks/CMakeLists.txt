cmake_minimum_required(VERSION 3.9)
project(shadowsocks)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(crypto_utils)
add_subdirectory(plugin_utils)
add_subdirectory(ss_proto)

list(APPEND DEPS
     Boost::program_options
     common_utils
     crypto_utils
     plugin_utils
     protocol_hooks
     ss_proto
     ${COMMON_DEPS}
     Threads::Threads
    )

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tunnel)

