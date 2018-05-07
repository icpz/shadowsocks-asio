cmake_minimum_required(VERSION 3.9)
project(simple-obfs)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(obfs_utils)

add_subdirectory(client)
add_subdirectory(server)

