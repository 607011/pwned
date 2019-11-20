cmake_minimum_required(VERSION 2.8)

project(mphf-test)

add_executable(mphf-test mphf.cpp)
set_target_properties(mphf-test PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(mphf-test
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(mphf-test
	pwned
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
)
