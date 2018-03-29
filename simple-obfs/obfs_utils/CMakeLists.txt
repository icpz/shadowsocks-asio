cmake_minimum_required(VERSION 3.9)
project(obfs_utils)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

list(APPEND DEPS
     common_utils
     protocol_hooks
     ${COMMON_DEPS}
    )

list(APPEND SOURCES
     src/obfs.cc
     src/tls.cc
    )

add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
else()
    install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
endif()
