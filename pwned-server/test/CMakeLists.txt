cmake_minimum_required(VERSION 2.8)

project(tests)

find_package(Boost 1.71.0 COMPONENTS unit_test_framework REQUIRED)

add_executable(test_uri_executable test_uri.cpp ../uri.cpp)
target_include_directories(test_uri_executable
  PRIVATE ${BOOST_INCLUDE_DIRS}
  ${PROJECT_INCLUDE_DIRS})
target_link_libraries(test_uri_executable pwned
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
  ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
)
target_compile_definitions(test_uri_executable PRIVATE "BOOST_TEST_DYN_LINK=1")
add_test(NAME test_uri COMMAND test_uri_executable)
