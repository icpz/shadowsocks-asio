cmake_minimum_required(VERSION 3.9)
project(common_utils)

set(CMAKE_CXX_STANDARD 14)

list(APPEND BOOST_DEPS
     boost_log-mt
     boost_thread-mt
     boost_system-mt
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

list(APPEND SOURCES
     src/socks5.cc
    )

add_library(${PROJECT_NAME} STATIC ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${BOOST_DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

