cmake_minimum_required(VERSION 3.2)

project(pwned-merger-cli)

add_executable(pwned-merger-cli pwned-merger-cli.cpp mergeoperation.cpp)
set_target_properties(pwned-merger-cli PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-merger-cli
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-merger-cli pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
