cmake_minimum_required(VERSION 3.2)

project(pwned-index)

add_executable(pwned-index index.cpp)
set_target_properties(pwned-index PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-index
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pwned-index
  pnwed
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${Boost_LIBRARIES}
)
