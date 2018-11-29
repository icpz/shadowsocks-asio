cmake_minimum_required(VERSION 3.9)
project(plugin_utils)

set(CMAKE_CXX_STANDARD 14)

set(DEPS
    common_utils
    Boost::filesystem
    ${COMMON_DEPS}
   )

set(SOURCES
    src/plugin.cc
   )

add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

