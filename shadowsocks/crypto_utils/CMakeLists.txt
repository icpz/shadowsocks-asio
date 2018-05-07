cmake_minimum_required(VERSION 3.9)
project(crypto_utils)

set(CMAKE_CXX_STANDARD 14)

if(APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_search_module(LIBSODIUM REQUIRED libsodium)
    include_directories(${LIBSODIUM_INCLUDE_DIRS})
    set(LIBSODIUM ${LIBSODIUM_LDFLAGS})

    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
elseif(WIN32)
    add_definitions(-DSODIUM_STATIC)
    find_path(LIBSODIUM_INC sodium.h)
    find_library(LIBSODIUM NAMES libsodium)
else()
    set(LIBSODIUM "-lsodium")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 1.0.2 REQUIRED)

if(${OPENSSL_VERSION} VERSION_GREATER_EQUAL 1.1)
    message(FATAL_ERROR "libcrypto too new, require <= 1.0.2")
endif()

list(APPEND DEPS
     common_utils
     OpenSSL::Crypto
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

