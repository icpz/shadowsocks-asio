cmake_minimum_required(VERSION 3.13.0)
project(obfs_utils)

set(CMAKE_CXX_STANDARD 14)

set(DEPS
    common_utils
    protocol_hooks
    ${COMMON_DEPS}
   )

set(SOURCES
    src/obfs.cc
    src/obfs_proto.cc
    src/tls.cc
    src/http.cc
   )

add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

