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
#include <fstream>
#include <exception>
#include <boost/locale/encoding_utf.hpp>

#include <pwned-lib/userpasswordreader.hpp>
#include <pwned-lib/markovnode.hpp>
#include <pwned-lib/markovchain.hpp>

namespace markov = pwned::markov;

std::wstring to_utf32(const std::string &s)
{
  return boost::locale::conv::utf_to_utf<wchar_t>(s.c_str(), s.c_str() + s.size());
}

std::string to_utf8(wchar_t c)
{
  return boost::locale::conv::utf_to_utf<char>(std::wstring(&c, 1));
}

int main(int argc, char* argv[])
{
  if (argc < 3)
    return EXIT_FAILURE;
  const std::string &inputFilename = argv[1];
  const std::string &outputFilename = argv[2];
  std::istream *input = &std::cin;
  std::ifstream inputFile;
  if (inputFilename != "-")
  {
    inputFile.open(inputFilename);
    input = &inputFile;
  }
  const std::vector<pwned::UserPasswordReaderOptions> readerOptions{pwned::UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords};
  pwned::UserPasswordReader reader(*input, readerOptions);
  uint64_t n = 0;
  markov::Chain chain;
  while (!reader.eof())
  {
    const std::string &pwd = reader.nextPassword();
    const std::wstring &s32 = to_utf32(pwd);
    try
    {
      if (pwd.size() > 1)
      {
        for (std::size_t i = 0; i < s32.size() - 1; ++i)
        {
          chain.addPair(s32.at(i), s32.at(i+1));
        }
        ++n;
      }
    }
    catch (const std::exception &e)
    {
      std::cerr << "ERROR: " << e.what() << " (password=" << pwd << ")" << std::endl;
    }
  }
  std::cout << "passwords written: " << n << std::endl;
  chain.update();
  std::ofstream output(outputFilename, std::ios::trunc | std::ios::binary);
  chain.writeBinary(output);
  output.close();
  return EXIT_SUCCESS;
}