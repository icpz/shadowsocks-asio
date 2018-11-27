cmake_minimum_required(VERSION 3.9)
project(ss_proto)

set(CMAKE_CXX_STANDARD 14)

set(DEPS
    common_utils
    crypto_utils
    protocol_hooks
    ${COMMON_DEPS}
   )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SOURCES
    src/client.cc
    src/server.cc
    src/tunnel.cc
   )

add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

