cmake_minimum_required(VERSION 3.2)

project(pwned_lib)

add_library(pnwed STATIC
	hash.cpp
	operation.cpp
	passwordinspector.cpp
	util.cpp
	uuid.cpp)

if($ENV{NO_POPCNT})
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mno-popcnt -DNO_POPCNT")
else()
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -mpopcnt -DUSE_POPCNT")
endif()

target_include_directories(pnwed PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set_target_properties(pnwed PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")
