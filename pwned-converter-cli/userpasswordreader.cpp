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

UserPasswordReader::UserPasswordReader(std::istream &inputStream, const std::vector<UserPasswordReaderOptions> &options)
    : input(inputStream)
{
  forceEvaluateMD5Hashes = std::find(options.begin(), options.end(), UserPasswordReaderOptions::forceEvaluateMD5Hashes) != options.end();
  forceEvaluateHexEncodedPasswords = std::find(options.begin(), options.end(), UserPasswordReaderOptions::forceEvaluateHexEncodedPasswords) != options.end();
  autoEvaluateMD5Hashes = std::find(options.begin(), options.end(), UserPasswordReaderOptions::autoEvaluateMD5Hashes) != options.end();
  autoEvaluateHexEncodedPasswords = std::find(options.begin(), options.end(), UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords) != options.end();
  evaluateContents();
}

bool UserPasswordReader::eof() const
{
  return input.eof();
}

bool UserPasswordReader::bad() const
{
  return input.bad();
}


char UserPasswordReader::guessSeparator()
{
  std::map<char, int> successfulSplits;
  static const std::vector<char> possibleSeparators{':', ';', '\t', ' '};
  std::string line;
  for (int i = 0; i < nTries && !eof(); ++i)
  {
    std::getline(input, line);
    line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
    for (char sep : possibleSeparators)
    {
      if (line.find(sep) != std::string::npos)
      {
        successfulSplits[sep] += 1;
      }
    }
  }
  if (!successfulSplits.empty())
  {
    using pair_type = decltype(successfulSplits)::value_type;
    auto maxSep = std::max_element(std::begin(successfulSplits),
                                   std::end(successfulSplits),
                                   [](const pair_type &a, const pair_type &b) {
                                     return a.second < b.second;
                                   });
    if (maxSep->second > 0)
    {
      guessedSeparator = maxSep->first;
    }
  }
  input.clear();
  input.seekg(0, std::ios::beg);
  return guessedSeparator;
}

bool UserPasswordReader::checkForMD5Hashes()
{
  if (!forceEvaluateMD5Hashes && autoEvaluateMD5Hashes)
  {
    std::string line;
    for (int i = 0; i < nTries && !eof(); ++i)
    {
      std::getline(input, line);
      line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
      if (line.find(guessedSeparator) != std::string::npos)
      {
        if (std::regex_search(line, MD5Regex))
        {
          forceEvaluateMD5Hashes = true;
          break;
        }
      }
    }
  }
  input.clear();
  input.seekg(0, std::ios::beg);
  return forceEvaluateMD5Hashes;
}

bool UserPasswordReader::checkForHexEncodedPasswords()
{
  if (forceEvaluateHexEncodedPasswords)
    return true;
  if (autoEvaluateHexEncodedPasswords)
  {
    std::string line;
    for (int i = 0; i < nTries && !eof(); ++i)
    {
      std::getline(input, line);
      if (line.find(guessedSeparator) != std::string::npos)
      {
        if (std::regex_search(line, HexRegex))
        {
          forceEvaluateHexEncodedPasswords = true;
          break;
        }
      }
    }
  }
  input.clear();
  input.seekg(0, std::ios::beg);
  return forceEvaluateHexEncodedPasswords;
}

void UserPasswordReader::evaluateContents()
{
  this->guessSeparator();
  this->checkForHexEncodedPasswords();
  this->checkForMD5Hashes();
}

std::string UserPasswordReader::extractPassword(std::string line)
{
  line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
  if (guessedSeparator != '\0')
  {
    const size_t pos = line.find(guessedSeparator);
    return (pos == std::string::npos)
              ? line
              : line.substr(pos + 1);
  }
  return line;
}

Hash UserPasswordReader::nextPasswordHash()
{
  if (input.eof() || input.bad())
    return Hash();
  std::getline(input, currentLine);
  ++lineNo;
  if (currentLine.size() > 200 || currentLine.size() < 1) // assume no user:pass line is longer than 200 characters
    return Hash();
  std::string pwd = extractPassword(currentLine);
  if (pwd.size() == 0)
    return Hash();
  Hash hash;
  if (forceEvaluateMD5Hashes)
  {
    std::smatch match;
    if (std::regex_match(pwd, match, MD5Regex))
    {
      hash = pwned::Hash::fromHex(match[0]);
    }
  }
  if (!hash.isValid)
  {
    if (forceEvaluateHexEncodedPasswords)
    {
      std::smatch match;
      if (std::regex_match(pwd, match, HexRegex))
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
    ++validEntries;
  }
  return hash;
}

} // namespace pwned
