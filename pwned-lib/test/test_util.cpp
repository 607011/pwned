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

#define BOOST_TEST_MODULE test util
#define BOOST_TEST_MODULE_UTIL

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <boost/test/unit_test.hpp>
#include "pwned-lib/util.hpp"

BOOST_AUTO_TEST_SUITE(test_util)

BOOST_AUTO_TEST_CASE(test_popcnt)
{
  BOOST_TEST(pwned::popcnt64(0) == 0);
  for (unsigned int i = 0; i < 8 * sizeof(uint64_t); ++i)
  {
    BOOST_TEST(pwned::popcnt64(1ULL << i) == 1);
  }
  for (unsigned int i = 1; i < 8 * sizeof(uint64_t); ++i)
  {
    BOOST_TEST(pwned::popcnt64((1ULL << i) - 1) == i);
  }
  BOOST_TEST(pwned::popcnt64(0b0101010101010101010101010101010101010101010101010101010101010101) == 32);
  BOOST_TEST(pwned::popcnt64(0b1010101010101010101010101010101010101010101010101010101010101010) == 32);
}

BOOST_AUTO_TEST_CASE(test_decodehex_lowercase)
{
  static const char hexDigitsLower[16]{
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };
  for (int i = 0; i < 16; ++i)
  {
    BOOST_TEST(pwned::decodeHex(hexDigitsLower[i]) == i);
  }
}

BOOST_AUTO_TEST_CASE(test_decodehex_uppercase)
{
  static const char hexDigitsUpper[16]{
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  };
  for (int i = 0; i < 16; ++i)
  {
    BOOST_TEST(pwned::decodeHex(hexDigitsUpper[i]) == i);
  }
}

BOOST_AUTO_TEST_CASE(test_decodehex_illegal)
{
  static const std::vector<int>legalHexDigits{
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f',
    'A', 'B', 'C', 'D', 'E', 'F'
  };
  for (int c = 0; c < 255; ++c)
  {
    if (std::find(std::begin(legalHexDigits), std::end(legalHexDigits), c) == legalHexDigits.end())
    {
      BOOST_TEST(pwned::decodeHex((char)c) < 0);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_readabletime)
{
  BOOST_TEST(pwned::readableTime(0.00001) == "0.0000s");
  BOOST_TEST(pwned::readableTime(0.000049) == "0.0000s");
  BOOST_TEST(pwned::readableTime(0.00005) == "0.0001s");
  BOOST_TEST(pwned::readableTime(0.0001) == "0.0001s");
  BOOST_TEST(pwned::readableTime(0.2) == "0.2000s");
  BOOST_TEST(pwned::readableTime(0.9999) == "0.9999s");
  BOOST_TEST(pwned::readableTime(60.5) == "1m 1s");
  BOOST_TEST(pwned::readableTime(90.0001) == "1m 30s");
  BOOST_TEST(pwned::readableTime(120 + 40.99) == "2m 41s");
  BOOST_TEST(pwned::readableTime(30*60 + 10) == "30m 10s");
  BOOST_TEST(pwned::readableTime(60*60 + 5) == "1h 0m 5s");
  BOOST_TEST(pwned::readableTime(12*60*60 + 20*60 + 12) == "12h 20m 12s");
  BOOST_TEST(pwned::readableTime(24*60*60 + 30*60 + 23) == "1d 0h 30m 23s");
  BOOST_TEST(pwned::readableTime(24*60*60 + 23*60*60 + 59*60 + 59) == "1d 23h 59m 59s");
  BOOST_TEST(pwned::readableTime(5*24*60*60) == "5d 0h 0m 0s");
  BOOST_TEST(pwned::readableTime(366*24*60*60 + 23*60*60 + 59*60 + 59.000001) == "366d 23h 59m 59s");
}

BOOST_AUTO_TEST_CASE(test_readablesize)
{
  static constexpr uint64_t K = 1024;
  static constexpr uint64_t M = K * K;
  static constexpr uint64_t G = M * K;
  static constexpr uint64_t T = G * K;
  BOOST_TEST(pwned::readableSize(0ULL) == "0 B");
  BOOST_TEST(pwned::readableSize(200ULL) == "200 B");
  BOOST_TEST(pwned::readableSize(1023ULL) == "1023 B");
  BOOST_TEST(pwned::readableSize(1024ULL) == "1024 B");
  BOOST_TEST(pwned::readableSize(1025ULL) == "1.0 KB");
  BOOST_TEST(pwned::readableSize(1025ULL + 500) == "1.5 KB");
  BOOST_TEST(pwned::readableSize(10240ULL) == "10.0 KB");
  BOOST_TEST(pwned::readableSize(256ULL*K + 300) == "256.3 KB");
  BOOST_TEST(pwned::readableSize(10ULL*M + 500) == "10.0 MB");
  BOOST_TEST(pwned::readableSize(10ULL*M + 500*1024) == "10.5 MB");
  BOOST_TEST(pwned::readableSize(99ULL*M + 513*1024) == "99.5 MB");
  BOOST_TEST(pwned::readableSize(5ULL*G + 400*M) == "5.4 GB");
  BOOST_TEST(pwned::readableSize(128ULL*T + 600*G) == "128.6 TB");
}

BOOST_AUTO_TEST_SUITE_END()
