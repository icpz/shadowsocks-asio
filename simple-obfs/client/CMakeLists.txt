cmake_minimum_required(VERSION 3.9)
project(obfs-client)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(DEPS
    Boost::program_options
    common_utils
    protocol_hooks
    obfs_utils
    Threads::Threads
    ${COMMON_DEPS}
   )

set(SOURCES
    src/server.cc
    src/parse_args.cc
    src/main.cc
   )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
