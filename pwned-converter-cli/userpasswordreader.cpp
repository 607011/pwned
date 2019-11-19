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

namespace pwned
{

class UserPasswordReaderPrivate
{
public:
  UserPasswordReaderPrivate(const std::string &inputFilePath)
      : inputFilePath(inputFilePath)
      , validEntries(0)
      , lineNo(0)
      , guessedSeparator(':')
      , approxBytesPerEntry(30)
      , HexRegex("\\$HEX\\[(.+?)\\]")
      , MD5Regex("[a-zA-Z0-9]{32}")
      , forceEvaluateHexEncodedPasswords(false)
      , forceEvaluateMD5Hashes(false)
      , autoEvaluateHexEncodedPasswords(false)
      , autoEvaluateMD5Hashes(false)
      , f(inputFilePath, std::ios::in | std::ios::binary)
  {
  }
  const std::string &inputFilePath;
  uint64_t validEntries;
  uint64_t lineNo;
  char guessedSeparator;
  float approxBytesPerEntry;
  std::regex HexRegex;
  std::regex MD5Regex;
  bool forceEvaluateHexEncodedPasswords;
  bool forceEvaluateMD5Hashes;
  bool autoEvaluateHexEncodedPasswords;
  bool autoEvaluateMD5Hashes;
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
  using pair_type = decltype(successfulSplits)::value_type;
  auto maxSep = std::max_element(std::begin(successfulSplits),
                                 std::end(successfulSplits),
                                 [](const pair_type &a, const pair_type &b) {
                                   return a.second < b.second;
                                 });
  d->guessedSeparator = maxSep->first;
  d->f.clear();
  d->f.seekg(0, std::ios_base::beg);
  if (!d->forceEvaluateMD5Hashes && d->autoEvaluateMD5Hashes)
  {
    for (i = 0; i < nTries && !eof(); ++i)
    {
      std::getline(d->f, line, '\r');
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
      std::getline(d->f, line, '\r');
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

static int decodeHex(const char c)
{
  int result = -1;
  if ('0' <= c && c <= '9')
  {
    result = c - '0';
  }
  else if ('a' <= c && c <= 'f')
  {
    result = c - 'a' + 10;
  }
  else if ('A' <= c && c <= 'A')
  {
    result = c - 'A' + 10;
  }
  return result;
}

static void hexToCharSeq(const std::string &seq, std::string &result)
{
  if (seq.size() % 2 == 0)
  {
    for (size_t i = 0; i < seq.size(); i += 2)
    {
      const int hi = decodeHex(seq.at(i));
      const int lo = decodeHex(seq.at(i + 1));
      if (lo >= 0 && hi >= 0)
      {
        const int b = hi * 16 + lo;
        result.push_back(char(b));
      }
      else
      {
        std::cerr << "invalid hex code: " << seq << std::endl;
      }
    }
  }
}

Hash UserPasswordReader::nextPasswordHash()
{
  Hash hash;
  std::getline(d->f, d->currentLine, '\r');
  if (d->f.eof() || d->f.bad())
    return hash;
  ++d->lineNo;
  if (d->currentLine.size() > 200 || d->currentLine.size() < 1) // assume no user:pass line is longer than 200 characters
    return hash;
  const size_t pos = d->currentLine.find(d->guessedSeparator);
  if (pos == std::string::npos)
    return hash;
  const std::string &pwd = d->currentLine.substr(pos + 1);
  if (pwd.size() > 0)
  {
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
  }
  return hash;
}

} // namespace pwned
