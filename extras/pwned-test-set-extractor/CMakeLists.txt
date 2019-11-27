cmake_minimum_required(VERSION 2.8)

project(pwned-test-set-extractor)

add_executable(pwned-test-set-extractor test-set-extractor.cpp)
set_target_properties(pwned-test-set-extractor PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-test-set-extractor
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-test-set-extractor pwned ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})

install(TARGETS pwned-test-set-extractor)
