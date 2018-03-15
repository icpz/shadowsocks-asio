cmake_minimum_required(VERSION 3.9)
project(socks5-proxy)

set(CMAKE_CXX_STANDARD 14)

add_definitions(-DBOOST_ALL_DYN_LINK)

list(APPEND BOOST_DEPS
     boost_log-mt
     boost_thread-mt
     boost_program_options-mt
     boost_system-mt
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

list(APPEND SOURCES
     src/server.cc
     src/main.cc
     src/basic_protocol.cc
    )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${BOOST_DEPS})

