cmake_minimum_required(VERSION 3.2)

project(benchmark)

add_executable(benchmark benchmark.cpp)
set_target_properties(benchmark PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(benchmark
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(benchmark pnwed ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})
