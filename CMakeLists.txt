cmake_minimum_required(VERSION 3.2)
project(socks5-server)

set(CMAKE_CXX_STANDARD 14)

add_definitions(-DBOOST_ALL_DYN_LINK)

list(APPEND BOOST_DEPS
     boost_log-mt
     boost_thread-mt
     boost_program_options-mt
     boost_system-mt
    )

list(APPEND SOURCES
     src/server.h
     src/server.cc
     src/socks5.h
     src/buffer.h
     src/main.cc
    )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${BOOST_DEPS})

