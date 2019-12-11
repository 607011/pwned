cmake_minimum_required(VERSION 2.8)

project(pwned_lib)

add_library(pwned STATIC
	hash.cpp
	userpasswordreader.cpp
	operation.cpp
	operationexception.cpp
  markovnode.cpp
  markovchain.cpp
	passwordinspector.cpp
	util.cpp
	uuid.cpp)

target_include_directories(pwned
  PRIVATE ${PROJECT_INCLUDE_DIRS}
  PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set_target_properties(pwned PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

add_subdirectory(test)
