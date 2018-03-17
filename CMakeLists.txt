cmake_minimum_required(VERSION 3.9)
project(socks5-proxy)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-missing-braces")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

add_definitions(-DBOOST_ALL_DYN_LINK)

add_subdirectory(common_utils)
add_subdirectory(protocol_plugins)
add_subdirectory(proxy_server)
add_subdirectory(crypto_utils)

