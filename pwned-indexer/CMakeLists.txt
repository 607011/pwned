cmake_minimum_required(VERSION 2.8)

project(pwned-indexer)

add_executable(pwned-indexer pwned-indexer.cpp)
set_target_properties(pwned-indexer PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-indexer
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pwned-indexer
  pnwed
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${Boost_LIBRARIES}
)
