cmake_minimum_required(VERSION 3.9)
project(simple-obfs)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(obfs_utils)

find_package(Threads REQUIRED)

list(APPEND DEPS
     boost_program_options
     common_utils
     protocol_hooks
     obfs_utils
     ${COMMON_DEPS}
     Threads::Threads
    )

add_subdirectory(client)

