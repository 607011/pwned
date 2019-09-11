cmake_minimum_required(VERSION 3.2)

project(pwned-lookup-cli)

add_executable(pwned-lookup-cli pwned-lookup-cli.cpp)
set_target_properties(pwned-lookup-cli PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-lookup-cli
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-lookup-cli pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
