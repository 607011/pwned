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
message(STATUS "Found BZ2 lib: ${bz2}")

if(APPLE)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lkmod")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_link_libraries(pwned-password-extractor
  pwned
  ${bz2}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${Boost_LIBRARIES}
)

install(TARGETS pwned-password-extractor RUNTIME DESTINATION bin)
