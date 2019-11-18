#define BOOST_TEST_MODULE test_hash

#include <boost/test/unit_test.hpp>

#include "pwned-lib/hash.hpp"

BOOST_AUTO_TEST_CASE(test_hash)
{
  BOOST_TEST(pwned::Hash("12345").toString() == "827ccb0eea8a706c4c34a16891f84e7b");
}
