#define BOOST_TEST_MODULE test passwordhashandcount
#define BOOST_TEST_MODULE_PHC

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstring>
#include <boost/test/unit_test.hpp>
#include "pwned-lib/passwordhashandcount.hpp"

BOOST_AUTO_TEST_SUITE(test_phc)

BOOST_AUTO_TEST_CASE(test_phc_const)
{
  BOOST_TEST(pwned::PasswordHashAndCount::size == 20);
}

BOOST_AUTO_TEST_CASE(test_phc_ctor)
{
  pwned::PasswordHashAndCount phc;
  BOOST_TEST(phc.count == 0);
  BOOST_TEST(phc.hash == pwned::Hash());
}

BOOST_AUTO_TEST_CASE(test_phc_read)
{
  pwned::PasswordHashAndCount phc;
  const uint8_t data[pwned::PHC::size] = {0x88U, 0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU, 0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0xefU, 0xbeU, 0xadU, 0xdeU};
  std::stringstream ss;
  for (size_t i = 0; i < pwned::PHC::size; ++i)
  {
    ss << data[i];
  }
  BOOST_TEST(phc.read(ss) == true);
  BOOST_TEST(phc.hash.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(phc.hash.lower == 0x7766554433221100ULL);
  BOOST_TEST(phc.count == 0xdeadbeef);
  BOOST_TEST(phc.read(ss) == false);
}

BOOST_AUTO_TEST_CASE(test_phc_misc)
{
  pwned::Hash hash = pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100");
  pwned::PasswordHashAndCount phc(hash, 2U<<31);
  BOOST_TEST(phc.hash.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(phc.hash.lower == 0x7766554433221100ULL);
  BOOST_TEST(phc.count == 2U<<31);
}

BOOST_AUTO_TEST_SUITE_END()
