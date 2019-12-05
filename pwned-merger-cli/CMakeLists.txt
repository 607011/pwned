cmake_minimum_required(VERSION 2.8)

project(pwned-merger-cli)

add_executable(pwned-merger-cli pwned-merger-cli.cpp mergeoperation.cpp)
set_target_properties(pwned-merger-cli PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-merger-cli
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

if(UNIX)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lpthread")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -pthread")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pthread")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_link_libraries(pwned-merger-cli pwned ${PLATFORM_DEPENDENT_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} ${Boost_LIBRARIES})

add_custom_command(TARGET pwned-merger-cli
  POST_BUILD
  COMMAND strip pwned-merger-cli)

install(TARGETS pwned-merger-cli RUNTIME DESTINATION bin)
