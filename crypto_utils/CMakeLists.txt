cmake_minimum_required(VERSION 3.9)
project(crypto_utils)

set(CMAKE_CXX_STANDARD 14)

if (APPLE)
    set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl@1.1/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    find_package(PkgConfig REQUIRED)

    pkg_search_module(LIBCRYPTO REQUIRED libcrypto>=1.1)
    pkg_search_module(LIBSODIUM REQUIRED libsodium)

    include_directories(${LIBCRYPTO_INCLUDE_DIRS})
    include_directories(${LIBSODIUM_INCLUDE_DIRS})
else()
    set(LIBCRYPTO_LDFLAGS "-lcrypto")
    set(LIBSODIUM_LDFLAGS "-lsodium")
endif()

list(APPEND DEPS
     common_utils
     ${LIBCRYPTO_LDFLAGS}
     ${LIBSODIUM_LDFLAGS}
     ${BOOST_DEPS}
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

list(APPEND SOURCES
     src/cipher.cc
     src/crypto.cc
     src/chacha20_poly1305_ietf.cc
     src/aes_gcm_family.cc
     src/aes_cfb_family.cc
    )

add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${DEPS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)

