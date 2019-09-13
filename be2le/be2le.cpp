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
#include <fstream>
#include <string>

#include <pwned-lib/passwordhashandcount.hpp>

int main(int argc, const char *argv[])
{
  if (argc < 3)
  {
    std::cerr << "Usage: be2le <md5_count_input_file> <md5_count_output_file>" << std::endl;
    return EXIT_FAILURE;
  }
  const std::string &inputFilename = argv[1];
  const std::string &outputFilename = argv[2];
  std::ifstream in(inputFilename, std::ios::binary);
  std::ofstream out(outputFilename, std::ios::binary | std::ios::trunc);
  std::cout << "Input file:  " << inputFilename << std::endl
            << "Output file: " << outputFilename << std::endl
            << "Converting to Little Endian ... " << std::flush;
  if (in.is_open() && out.is_open())
  {
    pwned::PasswordHashAndCount phc;
    while (!in.eof())
    {
      phc.read(in);
      phc.hash.toHostByteOrder();
      phc.dump(out);
    }
  }
  std::cout << std::endl
            << "Ready." << std::endl;
  return EXIT_SUCCESS;
}
