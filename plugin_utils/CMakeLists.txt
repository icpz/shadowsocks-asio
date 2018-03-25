cmake_minimum_required(VERSION 3.9)
project(plugin_utils)

set(CMAKE_CXX_STANDARD 14)

list(APPEND DEPS
     boost_system-mt
     boost_filesystem-mt
     common_utils
    )

list(APPEND SOURCES
     src/plugin.cc
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

