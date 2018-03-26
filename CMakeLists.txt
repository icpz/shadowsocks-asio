cmake_minimum_required(VERSION 3.9)
project(socks5-proxy)

set(CMAKE_SKIP_INSTALL_RPATH TRUE)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-missing-braces")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

add_definitions(-DBOOST_ALL_DYN_LINK)

list(APPEND BOOST_DEPS
    boost_log-mt
    boost_system-mt
    boost_thread-mt
    boost_filesystem-mt
    boost_program_options-mt
    )

set(THREADS_PREFER_PTHREAD_FLAG ON)

add_subdirectory(common_utils)
add_subdirectory(crypto_utils)
add_subdirectory(plugin_utils)
add_subdirectory(protocol_hooks)
add_subdirectory(shadowsocks)

