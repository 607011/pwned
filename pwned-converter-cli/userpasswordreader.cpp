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
#include <regex>
#include <fstream>
#include <map>
#include <algorithm>
#include <cstdint>

#include "userpasswordreader.hpp"
#include <pwned-lib/util.hpp>

namespace pwned
{

class UserPasswordReaderPrivate
{
public:
  UserPasswordReaderPrivate(const std::string &inputFilePath)
      : f(inputFilePath, std::ios::binary)
  {
  }
  uint64_t validEntries{0};
  uint64_t lineNo{0};
  char guessedSeparator{0};
  float approxBytesPerEntry{30};
  const std::regex HexRegex{"\\$HEX\\[(.+?)\\]"};
  const std::regex MD5Regex{"[a-zA-Z0-9]{32}"};
  bool forceEvaluateHexEncodedPasswords{false};
  bool forceEvaluateMD5Hashes{false};
  bool autoEvaluateHexEncodedPasswords{false};
  bool autoEvaluateMD5Hashes{false};
  std::ifstream f;
  std::string currentLine;
};

UserPasswordReader::UserPasswordReader(const std::string &inputFilePath, const std::vector<UserPasswordReaderOptions> &options)
    : d(std::unique_ptr<UserPasswordReaderPrivate>(new UserPasswordReaderPrivate(inputFilePath)))
{
  d->forceEvaluateMD5Hashes = std::find(options.begin(), options.end(), UserPasswordReaderOptions::forceEvaluateMD5Hashes) != options.end();
  d->forceEvaluateHexEncodedPasswords = std::find(options.begin(), options.end(), UserPasswordReaderOptions::forceEvaluateHexEncodedPasswords) != options.end();
  d->autoEvaluateMD5Hashes = std::find(options.begin(), options.end(), UserPasswordReaderOptions::autoEvaluateMD5Hashes) != options.end();
  d->autoEvaluateHexEncodedPasswords = std::find(options.begin(), options.end(), UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords) != options.end();
  evaluateContents();
}

UserPasswordReader::~UserPasswordReader()
{
  if (d->f.is_open())
  {
    d->f.close();
  }
}

bool UserPasswordReader::eof() const
{
  return d->f.eof();
}

bool UserPasswordReader::bad() const
{
  return d->f.bad();
}

void UserPasswordReader::evaluateContents()
{
  if (!d->f.is_open())
    return;
  const int nTries = 500;
  std::map<char, int> successfulSplits;
  static const std::vector<char> possibleSeparators = {':', ';', '\t', ' '};
  int i;
  std::string line;
  for (i = 0; i < nTries && !eof(); ++i)
  {
    std::getline(d->f, line);
    for (auto sep : possibleSeparators)
    {
      if (line.find(sep) != std::string::npos)
      {
        successfulSplits[sep] += 1;
      }
    }
  }
  if (successfulSplits.size() > 0)
  {
    using pair_type = decltype(successfulSplits)::value_type;
    auto maxSep = std::max_element(std::begin(successfulSplits),
                                   std::end(successfulSplits),
                                   [](const pair_type &a, const pair_type &b) {
                                     return a.second < b.second;
                                   });
    d->guessedSeparator = maxSep->first;
  }

  d->f.clear();
  d->f.seekg(0, std::ios_base::beg);
  if (!d->forceEvaluateMD5Hashes && d->autoEvaluateMD5Hashes)
  {
    for (i = 0; i < nTries && !eof(); ++i)
    {
      std::getline(d->f, line);
      if (line.find(d->guessedSeparator) != std::string::npos)
      {
        if (std::regex_match(line, d->MD5Regex))
        {
          d->forceEvaluateMD5Hashes = true;
          break;
        }
      }
    }
  }
  d->f.clear();
  d->f.seekg(0, std::ios_base::beg);
  if (!d->forceEvaluateHexEncodedPasswords && d->autoEvaluateHexEncodedPasswords)
  {
    for (i = 0; i < nTries && !eof(); ++i)
    {
      std::getline(d->f, line);
      if (line.find(d->guessedSeparator) != std::string::npos)
      {
        if (std::regex_match(line, d->HexRegex))
        {
          d->forceEvaluateHexEncodedPasswords = true;
          break;
        }
      }
    }
  }
  d->f.clear();
  d->f.seekg(0, std::ios_base::beg);
}

Hash UserPasswordReader::nextPasswordHash()
{
  if (d->f.eof() || d->f.bad())
    return Hash();
  std::getline(d->f, d->currentLine);
  ++d->lineNo;
  if (d->currentLine.size() > 200 || d->currentLine.size() < 1) // assume no user:pass line is longer than 200 characters
    return Hash();
  std::string pwd;
  if (d->guessedSeparator != 0)
  {
    const size_t pos = d->currentLine.find(d->guessedSeparator);
    pwd = (pos == std::string::npos)
              ? d->currentLine
              : d->currentLine.substr(pos + 1);
  }
  else
  {
    pwd = d->currentLine;
  }
  if (pwd.size() == 0)
    return Hash();
  Hash hash;
  if (d->forceEvaluateMD5Hashes)
  {
    std::smatch match;
    if (std::regex_match(pwd, match, d->MD5Regex))
    {
      hash = pwned::Hash::fromHex(match[0]);
    }
  }
  if (!hash.isValid)
  {
    if (d->forceEvaluateHexEncodedPasswords)
    {
      std::smatch match;
      if (std::regex_match(pwd, match, d->HexRegex))
      {
        std::string dehexed;
        hexToCharSeq(match[1], dehexed);
        hash = Hash(dehexed);
      }
    }
    if (!hash.isValid)
    {
      hash = Hash(pwd);
    }
  }
  if (hash.isValid)
  {
    ++d->validEntries;
  }
  return hash;
}

} // namespace pwned
