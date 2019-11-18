cmake_minimum_required(VERSION 2.8.7)

project(test_hash)

add_executable(test_hash_executable test_hash.cpp)

target_include_directories(test_hash_executable
  PRIVATE ${BOOST_INCLUDE_DIRS}
  ${PROJECT_INCLUDE_DIRS})

find_package(Boost 1.71.0 COMPONENTS unit_test_framework REQUIRED)

target_compile_definitions(test_hash_executable PRIVATE "BOOST_TEST_DYN_LINK=1")

target_link_libraries(test_hash_executable pnwed
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
  ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
)

add_test(NAME test_hash COMMAND test_hash_executable)

