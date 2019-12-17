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

#define BOOST_TEST_MODULE test markov
#define BOOST_TEST_MODULE_MARKOV

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <sstream>
#include <cstring>
#include <cmath>
#include <limits>
#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <boost/locale/encoding_utf.hpp>

#include "pwned-lib/markovnode.hpp"
#include "pwned-lib/markovchain.hpp"
#include "pwned-lib/userpasswordreader.hpp"

BOOST_AUTO_TEST_SUITE(test_markov)

using symbol_type = wchar_t;
using prob_value_type = double;
namespace markov = pwned::markov;
namespace fs = boost::filesystem;

bool fuzzyEqual(prob_value_type a, prob_value_type b)
{
  return fabs(a - b) < std::numeric_limits<prob_value_type>::epsilon();
}

std::basic_string<symbol_type> widen(std::string s)
{
  return boost::locale::conv::utf_to_utf<symbol_type>(s);
}

BOOST_AUTO_TEST_CASE(test_markov_rw)
{
  std::stringstream input;
  input << "abcdef\n"
           "12345\n"
           "0000\n"
           "0123";
  std::vector<pwned::UserPasswordReaderOptions> readerOptions{pwned::UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords};
  pwned::UserPasswordReader reader(input, readerOptions);
  markov::Chain<symbol_type, prob_value_type> chain;
  while (!reader.eof())
  {
    const std::string &pwd = reader.nextPassword();
    bool ok = chain.train(pwd);
    BOOST_ASSERT(ok);
  }
  chain.update();
  BOOST_ASSERT(chain.firstSymbolProbs().size() == 3);
  BOOST_ASSERT(chain.nodes().size() == 10);
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("pwd")), 0));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("1234")), 0.25));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("abc")), 0.25));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("01")), 0.125));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("012")), 0.125));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("0")), 0.5));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("00")), 0.375));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("000")), 0.28125));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("0000")), 0.210938));

  const fs::path outFilepath = fs::temp_directory_path() / fs::unique_path();
  std::ofstream outFile(outFilepath.string(), std::ios::binary);
  chain.writeBinary(outFile);
  outFile.close();

  std::ifstream inFile(outFilepath.string(), std::ios::binary);
  markov::Chain<>::ErrCode rc = chain.readBinary(inFile);
  inFile.close();
  BOOST_ASSERT(chain.firstSymbolProbs().size() == 3);
  BOOST_ASSERT(chain.nodes().size() == 10);
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("pwd")), 0));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("1234")), 0.25));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("abc")), 0.25));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("01")), 0.125));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("012")), 0.125));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("0")), 0.5));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("00")), 0.375));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("000")), 0.28125));
  BOOST_ASSERT(fuzzyEqual(chain.totalProbability(widen("0000")), 0.210938));
  fs::remove(outFilepath);
}

BOOST_AUTO_TEST_SUITE_END()
