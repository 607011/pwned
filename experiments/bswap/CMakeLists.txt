cmake_minimum_required(VERSION 3.2)

project(bswap)

add_executable(bswap bswap.cpp)
set_target_properties(bswap PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(bswap
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
