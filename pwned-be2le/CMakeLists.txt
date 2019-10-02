cmake_minimum_required(VERSION 2.8)

project(pwned-be2le)

add_executable(pwned-be2le pwned-be2le.cpp)
set_target_properties(pwned-be2le PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-be2le
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-be2le pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
