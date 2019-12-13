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

#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <iterator>
#include <fstream>
#include <exception>
#include <boost/locale/encoding_utf.hpp>

#include <pwned-lib/markovnode.hpp>
#include <pwned-lib/markovchain.hpp>

namespace markov = pwned::markov;

using symbol_type = wchar_t;
using prob_value_type = double;
using chain_type = markov::Chain<symbol_type, prob_value_type>;

prob_value_type totalProbability(const std::basic_string<symbol_type> &pwd, const chain_type &chain)
{
  if (pwd.empty())
    return -1;
  const auto &firstSymbol = chain.firstSymbolProbs().at(pwd.at(0));
  auto node = chain.nodes().at(firstSymbol.first);
  prob_value_type p = firstSymbol.second;
  for (auto c = std::next(std::begin(pwd)); c != std::end(pwd); ++c)
  {
    p *= node.probability(*c);
    // XXX
  }
  return p;
}

int main(int argc, char* argv[])
{
  if (argc < 2)
    return EXIT_FAILURE;
  const std::string &inputFilename = argv[1];
  std::ifstream inputFile(inputFilename, std::ios::binary);
  chain_type chain;
  chain.readBinary(inputFile);
  while (true)
  {
    std::string pwd;
    std::cin >> pwd;
    if (pwd.empty())
      break;
    const std::basic_string<symbol_type> &wPwd = boost::locale::conv::utf_to_utf<symbol_type>(pwd.c_str(), pwd.c_str() + pwd.size());
    std::cout << "p = " << totalProbability(wPwd, chain) << std::endl;
  }
  return EXIT_SUCCESS;
}
