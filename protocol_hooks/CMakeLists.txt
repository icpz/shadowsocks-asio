cmake_minimum_required(VERSION 3.9)
project(protocol_hooks)

set(CMAKE_CXX_STANDARD 14)

set(DEPS
    common_utils
    ${COMMON_DEPS}
   )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SOURCES
    src/basic_protocol.cc
   )

add_library(${PROJECT_NAME} STATIC ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

