cmake_minimum_required(VERSION 3.9)
project(socks5-proxy)

set(CMAKE_SKIP_INSTALL_RPATH TRUE)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-missing-braces")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

list(APPEND COMMON_DEPS
     boost_system
     glog
     gflags
    )

if(WINDOWS)
    add_definitions(-DWINDOWS)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)

add_subdirectory(common_utils)
add_subdirectory(protocol_hooks)
add_subdirectory(shadowsocks)
add_subdirectory(simple-obfs)

