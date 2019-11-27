cmake_minimum_required(VERSION 2.8)

project(pwned)

enable_testing()

cmake_policy(SET CMP0054 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -ggdb -DDEBUG -Wall -Wextra -Wconversion -Wreorder -Wuninitialized -Wtype-limits -Wno-pragmas")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wconversion -Wno-pragmas")

if($ENV{USE_POPCNT})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mpopcnt -DUSE_POPCNT")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNO_POPCNT")
endif()

set(PROJECT_INCLUDE_DIRS ${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dirs: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OpenSSL ssl lib: ${OPENSSL_SSL_LIBRARY}")

set(BOOST_ROOT $ENV{BOOST_ROOT})
find_package(Boost 1.71.0 COMPONENTS program_options chrono date_time filesystem system thread REQUIRED)
message(STATUS "Boost include dirs: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost lib dirs: ${Boost_LIBRARY_DIRS}")
message(STATUS "Boost libs: ${Boost_LIBRARIES}")

add_subdirectory(pwned-lib)
add_subdirectory(pwned-converter-cli)
add_subdirectory(pwned-merger-cli)
add_subdirectory(pwned-index)
add_subdirectory(pwned-lookup-cli)
add_subdirectory(pwned-server)
add_subdirectory(extras)
add_subdirectory(deprecated)

install(TARGETS
  pwned-converter-cli
  pwned-merger-cli
  pwned-index
  pwned-lookup-cli
  pwned-server
)
