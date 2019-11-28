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

#define BOOST_TEST_MODULE test userpasswordreader
#define BOOST_TEST_MODULE_USERPASSWORDREADER

#include <iostream>
#include <string>
#include <vector>
#include <boost/test/unit_test.hpp>
#include "../userpasswordreader.hpp"

BOOST_AUTO_TEST_SUITE(test_userpasswordreader)

BOOST_AUTO_TEST_CASE(test_userpasswordreader_password_only)
{
  pwned::UserPasswordReader reader("../../../../pwned-converter-cli/test/4387.txt", std::vector<pwned::UserPasswordReaderOptions>{});
  const std::vector<std::string> hashes{
    "da83e82ca4ccd2d49f4793099dfb5fdb",
    "d94354ac9cf3024f57409bd74eec6b4c",
    "cd92a26534dba48cd785cdcc0b3e6bd1",
    "21232f297a57a5a743894a0e4a801fc3",
    "34d121532c2b19bfd00b83997e207424",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "26db95d875347aeff76efedb23668bc3",
    "aac7e9d039d627c6c59754f8533dd660",
    "215e49351f6d8b316c9ae1c524a7c009",
    "e3afed0047b08059d0fada10f400c1e5",
    "8d7f41945be4937b7c470da070255d33",
    "357742da3f7a2fcec0fcffa840db38ce",
    "98d081653aed0e54dbf8316cb4640de7",
    "34b339799d540a72bf1c408c0e68afdd",
    "fe4a8d1cc3ae7158c3f40899c190d16a",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "63a9f0ea7bb98050796b649e85481845",
    "4297f44b13955235245b2497399d7a93",
    "70a73f40ea03aff27aed659282db31c9",
    "b5829ffb92dbda49c2d98ff00acfc098",
    "8640540da140f70c46b7bca31743b393",
    "26ff7a4427e83cdb2b0c7d1558e31427",
    "dfd828ad46e81934947c3280390742e8",
    "ac95af977423127b08385897bde275cb",
    "3ffca08260070f894dd47244c034c216",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "99974f541e529d1425304e27772be176",
    "f0eb63005912fce8c66288a633229d9f",
    "432c871b61e55bf0a074cc824e984340",
    "cf04cb0a94c2084743ef97cbf3319848",
    "c55ea333d1bce645ff9a36bb7d812ff1",
    "78fa5fe2f5f6682e415e1a1ec607ba4c",
    "f02368945726d5fc2a14eb576f7276c0",
    "712f79adead18f54eac40a84887d82f5"
  };
  auto it = hashes.begin();
  while (!reader.eof())
  {
    BOOST_TEST(reader.nextPasswordHash() == pwned::Hash::fromHex(*it++));
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_mail_and_password)
{
  BOOST_TEST(true); // TODO
}

BOOST_AUTO_TEST_SUITE_END()
