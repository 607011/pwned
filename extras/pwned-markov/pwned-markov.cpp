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
#include <string>
#include <fstream>
#include <boost/locale/encoding_utf.hpp>

#include "markovnode.hpp"
#include "markovchain.hpp"

std::wstring to_utf32(const std::string &s)
{
  return boost::locale::conv::utf_to_utf<wchar_t>(s.c_str(), s.c_str() + s.size());
}

std::string to_utf8(wchar_t c)
{
  return boost::locale::conv::utf_to_utf<char>(std::wstring(&c, 1));
}

int main(int, char*[])
{
  markov::Chain chain;
  std::ifstream input("/home/ola/tmp/4427_cristalix-pe_found.txt");
  while (!input.eof())
  {
    std::string line;
    std::getline(input, line);
    if (line.size() == 0)
      continue;
    const std::wstring &s32 = to_utf32(line);
    for (std::size_t i = 0; i < s32.size() - 1; ++i)
    {
      chain.addPair(s32[i], s32[i+1]);
    }
  }
  chain.update();
  // for (const auto &node : chain.nodes())
  // {
  //   std::cout << to_utf8(node.first) << " -> ";
  //   std::cout << to_utf8(node.second.maxProbElement().first) << " " << (1e2*node.second.maxProbElement().second) << "%";
  //   // for (const auto &prob : node.second.successors())
  //   // {
  //   //   std::cout << "(" << to_utf8(prob.first) << ":" << (1e2*prob.second) << "%)";
  //   // }
  //   std::cout << std::endl;
  // }
  // std::cout << std::endl;
  std::ofstream output("bin", std::ios::trunc | std::ios::binary);
  chain.writeBinary(output);
  return 0;
}