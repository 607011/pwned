cmake_minimum_required(VERSION 2.8)

project(pwned-server)

add_executable(pwned-server pwned-server.cpp httpinspector.cpp)
set_target_properties(pwned-server PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-server
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

if(UNIX)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lpthread")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pthread")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pthread")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

find_package(cpprestsdk REQUIRED)
find_library(cpprestsdk-lib cpprest)
message(STATUS "cpprestsdk-lib = ${cpprestsdk-lib}")

target_link_libraries(pwned-server
	pnwed
	${OPENSSL_CRYPTO_LIBRARY}
	${OPENSSL_SSL_LIBRARY}
	${Boost_LIBRARIES}
	${cpprestsdk-lib}
)
