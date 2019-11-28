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

#include <algorithm>
#include <vector>
#include <boost/test/unit_test.hpp>
#include "pwned-lib/util.hpp"

BOOST_AUTO_TEST_SUITE(test_util)

BOOST_AUTO_TEST_CASE(test_decodehex_lowercase)
{
  const char hexDigitsLower[16]{
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
  const char hexDigitsUpper[16]{
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
  std::vector<int>legalHexDigits{
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

BOOST_AUTO_TEST_SUITE_END()
