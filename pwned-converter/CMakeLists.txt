cmake_minimum_required(VERSION 2.8)

project(pwned-converter)

add_executable(pwned-converter pwned-converter.cpp userpasswordreader.cpp convertoperation.cpp)
set_target_properties(pwned-converter PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-converter
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

if(UNIX)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lpthread")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pthread")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pthread")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_link_libraries(pwned-converter pnwed ${PLATFORM_DEPENDENT_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
