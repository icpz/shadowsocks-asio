cmake_minimum_required(VERSION 3.13.0)
project(common_utils)

set(CMAKE_CXX_STANDARD 14)

set(SOURCES
    src/socks5.cc
    src/common.cc
    src/util.cc
   )

add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${COMMON_DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

