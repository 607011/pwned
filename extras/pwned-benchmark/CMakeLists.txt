cmake_minimum_required(VERSION 2.8)

project(pwned-benchmark)

add_executable(pwned-benchmark benchmark.cpp)
set_target_properties(pwned-benchmark PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-benchmark
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR}
)

if(APPLE)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lkmod")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_link_libraries(pwned-benchmark
  pwned
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${Boost_LIBRARIES}
)

install(TARGETS pwned-benchmark)
