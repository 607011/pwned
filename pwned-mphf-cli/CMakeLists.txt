cmake_minimum_required(VERSION 3.2)

project(pwned-mphf-cli)

add_executable(pwned-mphf-cli pwned-mphf-cli.cpp)
set_target_properties(pwned-mphf-cli PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-mphf-cli
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(pwned-mphf-cli pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
