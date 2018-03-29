cmake_minimum_required(VERSION 3.9)
project(plugin_utils)

set(CMAKE_CXX_STANDARD 14)

if(WIN32)
    find_library(BOOSTFS NAMES
                 boost_filesystem
                 boost_filesystem-vc140-mt
                 boost_filesystem-vc140-mt-gd
                )
    list(APPEND DEPS ${BOOSTFS})
endif()

list(APPEND DEPS
     common_utils
     ${COMMON_DEPS}
    )

list(APPEND SOURCES
     src/plugin.cc
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

