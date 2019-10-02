cmake_minimum_required(VERSION 2.8)

project(pwned)

cmake_policy(SET CMP0054 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -Wall -g3 -glldb -ggdb -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wno-#pragma-messages")

if($ENV{NO_POPCNT})
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mno-popcnt -DNO_POPCNT")
else()
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mpopcnt -DUSE_POPCNT")
endif()

set(PROJECT_INCLUDE_DIRS ${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dirs: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")

find_package(Boost COMPONENTS program_options filesystem REQUIRED)
message(STATUS "Boost include dirs: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost lib dirs: ${Boost_LIBRARY_DIRS}")
message(STATUS "Boost libs: ${Boost_LIBRARIES}")

add_subdirectory(pwned-lib)
add_subdirectory(pwned-converter)
add_subdirectory(pwned-merger)
add_subdirectory(pwned-indexer)
add_subdirectory(pwned-mphf-gen)
add_subdirectory(pwned-lookup)
add_subdirectory(pwned-be2le)
add_subdirectory(pwned-test-set-extractor)
add_subdirectory(pwned-benchmark)
