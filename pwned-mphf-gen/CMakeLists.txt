cmake_minimum_required(VERSION 2.8)

project(pwned-mphf-gen)

add_executable(pwned-mphf-gen pwned-mphf-gen.cpp)
set_target_properties(pwned-mphf-gen PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

if(UNIX)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lpthread")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pthread")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pthread")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_include_directories(pwned-mphf-gen
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-mphf-gen pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
