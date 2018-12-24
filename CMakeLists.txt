cmake_minimum_required(VERSION 3.13.0)
project(shadowsocks-asio)

set(CMAKE_SKIP_INSTALL_RPATH TRUE)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)

add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)

if(NOT WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-missing-braces")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /O2")
endif()

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.65.0 REQUIRED COMPONENTS system filesystem program_options)
find_package(glog 0.3.4 REQUIRED)
find_package(Threads REQUIRED)

set(COMMON_DEPS
    Boost::system
    glog::glog
    ${CMAKE_DL_LIBS}
   )

if(WIN32)
    add_definitions(-DWINDOWS)
    add_definitions(-D_WIN32_WINNT=0x0600)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
elseif(UNIX AND NOT APPLE)
    add_definitions(-DLINUX)
endif()

add_subdirectory(cares_service)
add_subdirectory(common_utils)
add_subdirectory(protocol_hooks)
add_subdirectory(shadowsocks)
add_subdirectory(simple-obfs)

