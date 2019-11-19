cmake_minimum_required(VERSION 2.8)

project(tests)

set(BOOST_ROOT $ENV{BOOST_ROOT})
find_package(Boost 1.71.0 COMPONENTS filesystem unit_test_framework REQUIRED)

add_executable(test_hash_executable test_hash.cpp)
target_include_directories(test_hash_executable
  PRIVATE ${BOOST_INCLUDE_DIRS}
  ${PROJECT_INCLUDE_DIRS})
target_link_libraries(test_hash_executable
  pwned
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
  ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
)
target_compile_definitions(test_hash_executable PRIVATE "BOOST_TEST_DYN_LINK=1")
add_test(NAME test_hash COMMAND test_hash_executable)

add_executable(test_phc_executable test_phc.cpp)
target_include_directories(test_phc_executable
  PRIVATE ${BOOST_INCLUDE_DIRS}
  ${PROJECT_INCLUDE_DIRS})
target_link_libraries(test_phc_executable
  pwned
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
  ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
)
target_compile_definitions(test_phc_executable PRIVATE "BOOST_TEST_DYN_LINK=1")
add_test(NAME test_phc COMMAND test_phc_executable)

add_executable(test_inspector_executable test_inspector.cpp)
target_include_directories(test_inspector_executable
  PRIVATE ${BOOST_INCLUDE_DIRS}
  ${PROJECT_INCLUDE_DIRS})
target_link_libraries(test_inspector_executable
  pwned
	${OPENSSL_CRYPTO_LIBRARY}
	${Boost_LIBRARIES}
  ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}
)

target_compile_definitions(test_inspector_executable PRIVATE "BOOST_TEST_DYN_LINK=1")
add_test(NAME test_inspector COMMAND test_inspector_executable)
