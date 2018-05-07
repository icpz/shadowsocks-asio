cmake_minimum_required(VERSION 3.9)
project(shadowsocks)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(crypto_utils)
add_subdirectory(plugin_utils)
add_subdirectory(ss_proto)

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tunnel)

