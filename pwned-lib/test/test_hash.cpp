#define BOOST_TEST_MODULE test hash
#define BOOST_TEST_MODULE_HASH

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstring>
#include <boost/test/unit_test.hpp>
#include "pwned-lib/hash.hpp"

BOOST_AUTO_TEST_SUITE(test_hash)

BOOST_AUTO_TEST_CASE(test_hash_const)
{
  BOOST_TEST(pwned::Hash::size == 16);
}

BOOST_AUTO_TEST_CASE(test_hash_ctor)
{
  pwned::Hash h0;
  BOOST_TEST(h0.lower == 0);
  BOOST_TEST(h0.upper == 0);
  BOOST_TEST(h0.isValid == false);
  pwned::Hash h1(0xffeeddccbbaa9988ULL, 0x7766554433221100ULL);
  BOOST_TEST(h1.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(h1.lower == 0x7766554433221100ULL);
  const uint8_t h1data[16] = {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  BOOST_TEST(std::memcmp(h1.data, h1data, pwned::Hash::size) == 0);
}

BOOST_AUTO_TEST_CASE(test_hash_read)
{
  pwned::Hash hash;
  const uint8_t data[pwned::Hash::size] = {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  std::stringstream ss;
  for (size_t i = 0; i < pwned::Hash::size; ++i)
  {
    ss << data[i];
  }
  BOOST_TEST(hash.read(ss) == true);
  BOOST_TEST(hash.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(hash.lower == 0x7766554433221100ULL);
  BOOST_TEST(hash.read(ss) == false);
}

BOOST_AUTO_TEST_CASE(test_hash_compare)
{
  pwned::Hash h0(0xffeeddccbbaa9988ULL, 0x7766554433221100ULL);
  pwned::Hash h1(h0);
  BOOST_TEST(h0 == h1);
  BOOST_TEST(h0 < pwned::Hash(0xffeeddccbbaa9989ULL, 0x7766554433221100ULL));
  BOOST_TEST(h0 < pwned::Hash(0xffeeddccbbaa9988ULL, 0x7766554433221101ULL));
  BOOST_TEST(h0 <= pwned::Hash(0xffeeddccbbaa9988ULL, 0x7766554433221100ULL));
  BOOST_TEST(h0 > pwned::Hash(0xffeeddccbbaa9988ULL, 0x1111111111111111ULL));
  BOOST_TEST(h0 > pwned::Hash(0xffeeddccbbaa9987ULL, 0x7766554433221100ULL));
  BOOST_TEST(h0 >= pwned::Hash(0xffeeddccbbaa9988ULL, 0x1111111111111111ULL));
  BOOST_TEST(h0 != pwned::Hash(0xffeeddccbbaa9988ULL, 0x1111111111111111ULL));
  BOOST_TEST(h0 != pwned::Hash(0xffeeddccbbaa9987ULL, 0x7766554433221100ULL));
  BOOST_TEST(h0 != pwned::Hash());
}

BOOST_AUTO_TEST_CASE(test_hash_fromhex)
{
  BOOST_TEST(pwned::Hash::fromHex("").isValid == false);
  BOOST_TEST(pwned::Hash::fromHex("beef").isValid == false);
  BOOST_TEST(pwned::Hash::fromHex("ffeeddccbbaa9988776655443322110").isValid == false);
  BOOST_TEST(pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100").isValid == true);
  BOOST_TEST(pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100").upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100").lower == 0x7766554433221100ULL);
}

BOOST_AUTO_TEST_CASE(test_hash_outputop)
{
  {
    std::ostringstream oss;
    pwned::Hash hash;
    oss << hash;
    BOOST_TEST(oss.str() == "00000000000000000000000000000000");
  }
  {
    std::ostringstream oss;
    pwned::Hash hash = pwned::Hash::fromHex("6fb42da0e32e07b61c9f0251fe627a9c");
    oss << hash;
    BOOST_TEST(oss.str() == "6fb42da0e32e07b61c9f0251fe627a9c");
  }
}

BOOST_AUTO_TEST_CASE(test_hash_from_string)
{
  BOOST_TEST(pwned::Hash("").toString() == "d41d8cd98f00b204e9800998ecf8427e");
  BOOST_TEST(pwned::Hash("1234").toString() == "81dc9bdb52d04dc20036dbd8313ed055");
  BOOST_TEST(pwned::Hash("12345").toString() == "827ccb0eea8a706c4c34a16891f84e7b");
  BOOST_TEST(pwned::Hash("qwertzuiop").toString() == "6415a104a4fb07f8b3be9a63464ebb87");
  BOOST_TEST(pwned::Hash("asdfghjkl").toString() == "c44a471bd78cc6c2fea32b9fe028d30a");
  BOOST_TEST(pwned::Hash("0000").toString() == "4a7d1ed414474e4033ac29ccb8653d9b");
  BOOST_TEST(pwned::Hash("0987654321").toString() == "6fb42da0e32e07b61c9f0251fe627a9c");
  BOOST_TEST(pwned::Hash("fucku").toString() == "4a621342de0b91d567690bd43e0c8894");
  BOOST_TEST(pwned::Hash("blahfasel").toString() == "0b8f59bb7e61b667bba91c780bda9f74");
  BOOST_TEST(pwned::Hash("yxcvbnm").toString() == "d9ec5f5e78aa7174e466f1ba50846627");
}

BOOST_AUTO_TEST_SUITE_END()
