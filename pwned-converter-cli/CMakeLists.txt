cmake_minimum_required(VERSION 3.2)

project(pwned-converter-cli)

add_executable(pwned-converter-cli pwned-converter-cli.cpp userpasswordreader.cpp convertoperation.cpp)
set_target_properties(pwned-converter-cli PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-converter-cli
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(pwned-converter-cli pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
