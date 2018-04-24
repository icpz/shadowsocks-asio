cmake_minimum_required(VERSION 3.9)
project(shadowsocks-asio)

set(CMAKE_SKIP_INSTALL_RPATH TRUE)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-missing-braces")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

    find_library(BOOSTSYS boost_system)
    find_library(BOOSTPO  boost_program_options)
    find_library(GLOG     glog)
    find_library(GFLAGS   gflags)
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /O2")

    find_path(BOOST_INC   boost/asio.hpp)
    find_library(BOOSTSYS NAMES boost_system boost_system-vc140-mt boost_system-vc140-mt-gd)
    find_library(
        BOOSTPO NAMES
        boost_program_options
        boost_program_options-vc140-mt
        boost_program_options-vc140-mt-gd
    )

    find_package(glog REQUIRED)
    find_package(gflags REQUIRED)
    set(GLOG glog::glog)
    set(GFLAGS gflags)
endif()

list(APPEND COMMON_DEPS
     ${BOOSTSYS}
     ${GLOG}
     ${GFLAGS}
    )

if(WIN32)
    add_definitions(-DWINDOWS)
elseif(UNIX AND NOT APPLE)
    add_definitions(-DLINUX)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)

add_subdirectory(common_utils)
add_subdirectory(protocol_hooks)
add_subdirectory(shadowsocks)
add_subdirectory(simple-obfs)

