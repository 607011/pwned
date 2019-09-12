cmake_minimum_required(VERSION 3.2)

project(pwned_lib)

add_library(pnwed STATIC
	hash.cpp
	operation.cpp
	passwordinspector.cpp
	util.cpp
	uuid.cpp)

target_include_directories(pnwed PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set_target_properties(pnwed PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")
