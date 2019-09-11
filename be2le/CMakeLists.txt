cmake_minimum_required(VERSION 3.2)

project(be2le)

add_executable(be2le be2le.cpp)
set_target_properties(be2le PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(be2le
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(be2le pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
