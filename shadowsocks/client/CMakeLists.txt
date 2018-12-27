cmake_minimum_required(VERSION 3.9)
project(ss-client)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SOURCES
    src/server.cc
    src/parse_args.cc
    src/main.cc
   )

set(DEPS
    common_utils
    crypto_utils
    plugin_utils
    protocol_hooks
    ss_proto
    Threads::Threads
    Boost::program_options
    ${COMMON_DEPS}
   )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
if (WIN32)
    target_link_options(${PROJECT_NAME} PRIVATE "LINKER:/FORCE:MULTIPLE")
endif (WIN32)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

