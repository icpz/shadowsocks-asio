cmake_minimum_required(VERSION 3.9)
project(proxy-server)

set(CMAKE_CXX_STANDARD 14)

list(APPEND BOOST_DEPS
     boost_log-mt
     boost_thread-mt
     boost_program_options-mt
     boost_system-mt
    )

list(APPEND DEPS
     common_utils
     -force_load crypto_utils
     protocol_plugins
     ${BOOST_DEPS}
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

list(APPEND SOURCES
     src/server.cc
     src/main.cc
    )

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})

