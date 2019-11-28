cmake_minimum_required(VERSION 2.8)

project(tests)

set(BOOST_ROOT $ENV{BOOST_ROOT})
find_package(Boost 1.71.0 COMPONENTS filesystem unit_test_framework REQUIRED)

add_executable(test_userpasswordreader_executable test_userpasswordreader.cpp ../userpasswordreader.cpp)
target_include_directories(test_userpasswordreader_executable
  PRIVATE ${BOOST_INCLUDE_DIRS}
  ${PROJECT_INCLUDE_DIRS})
target_link_libraries(test_userpasswordreader_executable
  pwned
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
  ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
)
target_compile_definitions(test_userpasswordreader_executable PRIVATE "BOOST_TEST_DYN_LINK=1")
add_test(NAME test_userpasswordreader COMMAND test_userpasswordreader_executable)
