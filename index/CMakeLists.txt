cmake_minimum_required(VERSION 3.2)

project(index)

add_executable(index index.cpp)
set_target_properties(index PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(index
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(index
  pnwed
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${Boost_LIBRARIES}
)
