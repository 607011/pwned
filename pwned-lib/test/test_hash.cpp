/*
 Copyright © 2019 Oliver Lau <ola@ct.de>, Heise Medien GmbH & Co. KG - Redaktion c't

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
  BOOST_TEST(h0.quad.lower == 0);
  BOOST_TEST(h0.quad.upper == 0);
  BOOST_TEST(h0.isValid == false);
  pwned::Hash h1(0xffeeddccbbaa9988ULL, 0x7766554433221100ULL);
  BOOST_TEST(h1.quad.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(h1.quad.lower == 0x7766554433221100ULL);
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
  BOOST_TEST(hash.quad.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(hash.quad.lower == 0x7766554433221100ULL);
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
  BOOST_TEST(pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100").quad.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100").quad.lower == 0x7766554433221100ULL);
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
  BOOST_TEST(pwned::Hash("Росси́я").toString() == "5d6e688cac4c420a7cbdb239ce137942");
  BOOST_TEST(pwned::Hash("日本").toString() == "4dbed2e657457884e67137d3514119b3");
  BOOST_TEST(pwned::Hash("中国").toString() == "c13dceabcb143acd6c9298265d618a9f");
  BOOST_TEST(pwned::Hash("한국").toString() == "afd6d52f9854f4fd442136e78a027f62");
  BOOST_TEST(pwned::Hash("ٱلْعَرَبِيَّة").toString() == "30382ccb8154718c5c40d8ad24532968");
  // see https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data
  std::string one_million_a(1'000'000, 'a');
  BOOST_TEST(pwned::Hash("abc").toString() == "900150983cd24fb0d6963f7d28e17f72");
  BOOST_TEST(pwned::Hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").toString() == "8215ef0796a20bcaaae116d3876c664a");
  BOOST_TEST(pwned::Hash(one_million_a).toString() == "7707d6ae4e027c70eea2a935c2296f21");
}

BOOST_AUTO_TEST_SUITE_END()
