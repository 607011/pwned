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

#ifndef __userpasswordreader_hpp__
#define __userpasswordreader_hpp__

#include <iostream>
#include <vector>
#include <regex>

#include "hash.hpp"

namespace pwned
{

enum UserPasswordReaderOptions
{
  forceEvaluateMD5Hashes,
  forceEvaluateHexEncodedPasswords,
  autoEvaluateMD5Hashes,
  autoEvaluateHexEncodedPasswords
};


class UserPasswordReader
{
public:
  UserPasswordReader(std::istream &inputStream, const std::vector<UserPasswordReaderOptions> &options);
  std::string extractPassword(const std::string &line);
  std::string nextPassword();
  Hash nextPasswordHash();
  bool eof() const;
  bool bad() const;

protected:
  void evaluateContents();
  char guessSeparator();
  bool checkForMD5Hashes();
  bool checkForHexEncodedPasswords();

private:
  static const int nTries{500};
  uint64_t validEntries{0};
  uint64_t lineNo{0};
  char guessedSeparator{'\0'};
  float approxBytesPerEntry{30};
  const std::regex HexRegex{"\\$HEX\\[((?:[a-zA-Z0-9][a-zA-Z0-9])+?)\\]"};
  const std::regex MD5Regex{"[a-zA-Z0-9]{32}"};
  bool forceEvaluateHexEncodedPasswords{false};
  bool forceEvaluateMD5Hashes{false};
  bool autoEvaluateHexEncodedPasswords{false};
  bool autoEvaluateMD5Hashes{false};
  std::istream &input;
  std::string currentLine;
};

} // namespace pwned

#endif // __userpasswordreader_hpp__
