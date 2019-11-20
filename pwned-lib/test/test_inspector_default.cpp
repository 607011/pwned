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

#define BOOST_TEST_MODULE test inspector default
#define BOOST_TEST_MODULE_HASH

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <fstream>
#include <cstring>
#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include "pwned-lib/hash.hpp"
#include "pwned-lib/passwordhashandcount.hpp"
#include "pwned-lib/passwordinspector.hpp"

BOOST_AUTO_TEST_SUITE(test_inspector_default)

BOOST_AUTO_TEST_CASE(test_existent_default)
{
  const std::string inputFilename = "../../../../pwned-lib/test/testset-10000-existent-collection1+2+3+4+5.md5";
  const uint64_t size = boost::filesystem::file_size(inputFilename);
  const uint64_t hashCount = size / pwned::PHC::size;
  std::vector<pwned::PHC> phcs;
  phcs.reserve(hashCount);
  std::ifstream testset(inputFilename, std::ios::binary);
  pwned::PasswordInspector inspector(inputFilename);
  pwned::PHC phc;
  uint64_t nFound = 0;
  while (phc.read(testset))
  {
    if (inspector.binsearch(phc.hash).count > 0)
    {
      ++nFound;
    }
  }
  BOOST_TEST(nFound == hashCount);
}

BOOST_AUTO_TEST_CASE(test_nonexistent_default)
{
  const std::string inputFilename = "../../../../pwned-lib/test/testset-10000-existent-collection1+2+3+4+5.md5";
  const std::string nonExistentInputFilename = "../../../../pwned-lib/test/testset-10000-nonexistent-collection1+2+3+4+5.md5";
  const uint64_t size = boost::filesystem::file_size(nonExistentInputFilename);
  const uint64_t hashCount = size / pwned::PHC::size;
  std::vector<pwned::PHC> phcs;
  phcs.reserve(hashCount);
  std::ifstream testset(nonExistentInputFilename, std::ios::binary);
  pwned::PasswordInspector inspector(inputFilename);
  pwned::PHC phc;
  uint64_t nNotFound = 0;
  while (phc.read(testset))
  {
    if (inspector.binsearch(phc.hash).count == 0)
    {
      ++nNotFound;
    }
  }
  BOOST_TEST(nNotFound == hashCount);
}

BOOST_AUTO_TEST_SUITE_END()
