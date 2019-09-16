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
#include <iomanip>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstdint>

#include <pwned-lib/passwordhashandcount.hpp>

constexpr uint64_t MASK = 0xffffff0000000000ULL;
constexpr int SHIFT = 40;
constexpr uint64_t MAXIDX = 0xffffffULL + 1ULL;

inline uint64_t extractIndex(uint64_t v)
{
  return (v & MASK) >> SHIFT;
}

int main(int argc, const char *argv[])
{
  std::string inputFilename;
  std::string outputFilename;
  if (argc == 3)
  {
    inputFilename = argv[1];
    outputFilename = argv[2];
  }
  else
  {
    return EXIT_FAILURE;
  }
  std::cout << "Scanning ..." << std::endl;
  std::ifstream input(inputFilename);
  pwned::PasswordHashAndCount phc;
  uint64_t *indexes = new uint64_t[MAXIDX];
  memset(indexes, 0xff, MAXIDX * sizeof(uint64_t));
  phc.read(input);
  uint64_t lastIdx = extractIndex(phc.hash.upper);
  *(indexes + lastIdx) = 0;
  uint64_t idx = 0;
  uint64_t pos = 0;
  while (!input.eof())
  {
    phc.read(input);
    idx = extractIndex(phc.hash.upper);
    if (idx > lastIdx)
    {
      pos = static_cast<uint64_t>(input.tellg()) - pwned::PasswordHashAndCount::size;
      *(indexes + idx) = pos;
      std::cout << "\r0x" << std::setfill('0') << std::setw(6) << std::hex << idx << " @ " << std::setw(0) << std::dec << pos << std::flush;
      lastIdx = idx;
    }
  }
  *(indexes + idx) = pos;
  input.close();

  std::cout << std::endl
            << "Writing ... " << std::flush;
  std::ofstream output(outputFilename, std::ios::trunc);
  output.write((const char *)indexes, MAXIDX * sizeof(uint64_t));
  output.close();
  delete[] indexes;
  std::cout << "Ready." << std::endl
            << std::endl;

  return EXIT_SUCCESS;
}