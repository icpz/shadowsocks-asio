cmake_minimum_required(VERSION 3.9)
project(crypto_utils)

set(CMAKE_CXX_STANDARD 14)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl@1.1/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()
find_package(PkgConfig REQUIRED)

pkg_search_module(LIBCRYPTO REQUIRED libcrypto)
pkg_search_module(LIBSODIUM REQUIRED libsodium)

list(APPEND BOOST_DEPS
     boost_log-mt
     boost_thread-mt
     boost_system-mt
    )

list(APPEND DEPS
     common_utils
     ${LIBCRYPTO_LDFLAGS}
     ${LIBSODIUM_LDFLAGS}
     ${BOOST_DEPS}
    )

include_directories(${LIBCRYPTO_INCLUDE_DIRS})
include_directories(${LIBSODIUM_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

list(APPEND SOURCES
     src/cipher.cc
     src/crypto.cc
     src/chacha20_poly1305_ietf.cc
    )

add_library(${PROJECT_NAME} STATIC ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

