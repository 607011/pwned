cmake_minimum_required(VERSION 2.8)

project(pwned-lookup)

add_executable(pwned-lookup pwned-lookup.cpp)
set_target_properties(pwned-lookup PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-lookup
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-lookup pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
