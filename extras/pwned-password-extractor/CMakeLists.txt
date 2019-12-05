cmake_minimum_required(VERSION 2.8)

project(pwned-password-extractor)

add_executable(pwned-password-extractor
  pwned-password-extractor.cpp
)
set_target_properties(pwned-password-extractor PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-password-extractor
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS}
)

find_library(bz2 bz2 PATHS /usr/lib /usr/local/lib)
if(bz2 STREQUAL "bz2-NOTFOUND")
  message(STATUS "BZ2 lib not found. Compiling without BZ2 support.")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DWITHOUT_BZ2")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DWITHOUT_BZ2")
else()
  message(STATUS "Found bz2 lib: ${bz2}")
  set(BZ2LIB bz2)
endif()

if(APPLE)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lkmod")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_link_libraries(pwned-password-extractor
  pwned
  ${BZ2LIB}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${Boost_LIBRARIES}
)

add_custom_command(TARGET pwned-password-extractor
  POST_BUILD
  COMMAND strip pwned-password-extractor)

install(TARGETS pwned-password-extractor RUNTIME DESTINATION bin)
