cmake_minimum_required(VERSION 3.9)
project(simple-obfs)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(obfs_utils)

find_package(Threads REQUIRED)

find_library(BOOSTPO NAMES
             boost_program_options
             boost_program_options-vc140-mt
             boost_program_options-vc140-mt-gd
            )

list(APPEND DEPS
     ${BOOSTPO}
     common_utils
     protocol_hooks
     obfs_utils
     ${COMMON_DEPS}
     Threads::Threads
    )

add_subdirectory(client)
