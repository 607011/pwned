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
  const uint8_t data[pwned::PHC::size] = {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xef, 0xbe, 0xad, 0xde};
  std::stringstream ss;
  for (size_t i = 0; i < pwned::PHC::size; ++i)
  {
    ss << data[i];
  }
  BOOST_TEST(phc.read(ss) == true);
  BOOST_TEST(std::memcmp(phc.hash.data, data, pwned::Hash::size) == 0);
  BOOST_TEST(phc.hash.quad.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(phc.hash.quad.lower == 0x7766554433221100ULL);
  BOOST_TEST(phc.count == 0xdeadbeef);
  BOOST_TEST(phc.read(ss) == false);
}

BOOST_AUTO_TEST_CASE(test_phc_misc)
{
  pwned::Hash hash = pwned::Hash::fromHex("ffeeddccbbaa99887766554433221100");
  pwned::PasswordHashAndCount phc(hash, 2U<<31);
  BOOST_TEST(phc.hash.quad.upper == 0xffeeddccbbaa9988ULL);
  BOOST_TEST(phc.hash.quad.lower == 0x7766554433221100ULL);
  BOOST_TEST(phc.count == 2U<<31);
}

BOOST_AUTO_TEST_SUITE_END()
