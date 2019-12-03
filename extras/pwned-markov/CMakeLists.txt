cmake_minimum_required(VERSION 2.8)

project(pwned-markov)

add_executable(pwned-markov
  pwned-markov.cpp
  markovnode.cpp
  markovchain.cpp
)
set_target_properties(pwned-markov PROPERTIES LINK_FLAGS_RELEASE "-dead_strip")

target_include_directories(pwned-markov
	PRIVATE ${PROJECT_INCLUDE_DIRS}
	PUBLIC ${Boost_INCLUDE_DIRS}
)

if(APPLE)
  set(PLATFORM_DEPENDENT_LIBRARIES, "-lkmod")
else()
  set(PLATFORM_DEPENDENT_LIBRARIES, "")
endif()

target_link_libraries(pwned-markov
  pwned
  ${OPENSSL_CRYPTO_LIBRARY}
  ${PLATFORM_DEPENDENT_LIBRARIES}
  ${Boost_LIBRARIES}
)

install(TARGETS pwned-markov RUNTIME DESTINATION bin)
