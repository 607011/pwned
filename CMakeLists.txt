cmake_minimum_required(VERSION 3.2)

project(pwned)

cmake_policy(SET CMP0054 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -Wall -g3 -glldb -ggdb -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

set(PROJECT_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/pwned-lib)

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dirs: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")

find_package(Boost COMPONENTS program_options chrono date_time filesystem REQUIRED)
message(STATUS "Boost include dirs: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost lib dirs: ${Boost_LIBRARY_DIRS}")
message(STATUS "Boost libs: ${Boost_LIBRARIES}")

add_subdirectory(pwned-lib)
add_subdirectory(pwned-converter-cli)
add_subdirectory(pwned-merger-cli)
add_subdirectory(pwned-lookup-cli)
add_subdirectory(be2le)
add_subdirectory(test-set-extractor)
add_subdirectory(benchmark)
