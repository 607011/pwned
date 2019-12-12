cmake_minimum_required(VERSION 2.8)

project(pwned-markov-generator)

add_executable(pwned-markov-generator pwned-markov.cpp)
set_target_properties(pwned-markov-generator PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-markov-generator
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS}
)

if(APPLE)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lkmod")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

find_library(bz2 bz2 PATHS /usr/lib /usr/local/lib)
if(bz2 STREQUAL "bz2-NOTFOUND")
  message(STATUS "BZ2 lib not found. Compiling without BZ2 support.")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DWITHOUT_BZ2")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DWITHOUT_BZ2")
else()
  message(STATUS "Found bz2 lib: ${bz2}")
  set(BZ2LIB bz2)
endif()

target_link_libraries(pwned-markov-generator
  pwned
  ${BZ2LIB}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${Boost_LIBRARIES}
)

add_custom_command(TARGET pwned-markov-generator
  POST_BUILD
  COMMAND strip pwned-markov-generator)

install(TARGETS pwned-markov-generator RUNTIME DESTINATION bin)
