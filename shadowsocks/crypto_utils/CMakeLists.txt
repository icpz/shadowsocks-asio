cmake_minimum_required(VERSION 3.9)
project(crypto_utils)

set(CMAKE_CXX_STANDARD 14)

if(APPLE)
    set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    find_package(PkgConfig REQUIRED)

    pkg_search_module(LIBCRYPTO REQUIRED libcrypto)
    pkg_search_module(LIBSODIUM REQUIRED libsodium)

    include_directories(${LIBCRYPTO_INCLUDE_DIRS})
    include_directories(${LIBSODIUM_INCLUDE_DIRS})

    set(LIBCRYPTO ${LIBCRYPTO_LDFLAGS})
    set(LIBSODIUM ${LIBSODIUM_LDFLAGS})
elseif(WIN32)
    find_path(LIBCRYPTO_INC openssl/evp.h)
    find_path(LIBSODIUM_INC sodium.h)
    find_library(LIBCRYPTO NAMES crypto)
    find_library(LIBSODIUM NAMES sodium)
else()
    set(LIBCRYPTO "-lcrypto")
    set(LIBSODIUM "-lsodium")
endif()

list(APPEND DEPS
     common_utils
     ${LIBCRYPTO}
     ${LIBSODIUM}
     ${COMMON_DEPS}
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

if(WIN32)
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
else()
    install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
endif()
