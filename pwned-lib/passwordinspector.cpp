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
#include <algorithm>
#include <limits>
#include <cmath>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <boost/filesystem.hpp>
#pragma GCC diagnostic pop

#include "passwordinspector.hpp"
#include "util.hpp"

namespace fs = boost::filesystem;

namespace pwned
{

template <typename T>
inline void safe_assign(T *a, T b)
{
  if (a != nullptr)
  {
    *a = b;
  }
}

PasswordInspector::PasswordInspector(const std::string &inputFilename)
{
  open(inputFilename);
}

PasswordInspector::PasswordInspector(const std::string &inputFilename, const std::string &indexFilename)
{
  open(inputFilename, indexFilename);
}

bool PasswordInspector::open(const std::string &filename)
{
  mFileSize = int64_t(fs::file_size(filename));
  mInputFile.open(filename, std::ios::binary);
  return mInputFile.is_open();
}

bool PasswordInspector::open(const std::string &inputFilename, const std::string &indexFilename)
{
  bool ok = open(inputFilename);
  if (!indexFilename.empty())
  {
    const uint64_t nKeys = uint64_t(fs::file_size(indexFilename) / sizeof(index_key_t));
    mShift = (unsigned int)(sizeof(index_key_t) * 8 - popcnt64(nKeys - 1));
    mIndexFile.open(indexFilename, std::ios::binary);
    ok = ok && mIndexFile.is_open();
  }
  return ok;
}

bool PasswordInspector::isOpen() const
{
  return mInputFile.is_open();
}

PasswordHashAndCount PasswordInspector::binsearch(const Hash &hash, int *readCount)
{
  int nReads = 0;
  std::streamoff lo = 0;
  std::streamoff hi = mFileSize;
  if (mIndexFile.is_open())
  {
    const uint64_t hashMSB = hash.quad.upper >> mShift;
    const std::streamoff idx = (std::streamoff)(hashMSB * sizeof(index_key_t));
    std::streamoff loIdx = idx;
    do {
      mIndexFile.seekg(loIdx);
      mIndexFile.read(reinterpret_cast<char*>(&lo), sizeof(index_key_t));
      ++nReads;
      loIdx -= sizeof(index_key_t);
    }
    while (lo == int64_t(std::numeric_limits<index_key_t>::max()));
    std::streamoff hiIdx = idx + (std::streamoff)sizeof(index_key_t);
    do {
      mIndexFile.seekg(hiIdx);
      mIndexFile.read(reinterpret_cast<char*>(&hi), sizeof(index_key_t));
      ++nReads;
      hiIdx += sizeof(index_key_t);
    }
    while (hi == int64_t(std::numeric_limits<index_key_t>::max()));
  }
  PasswordHashAndCount phc;
  while (lo <= hi)
  {
    std::streamoff pos = std::streamoff((uint64_t(lo) + uint64_t(hi)) / 2);
    pos -= pos % std::streamoff(PasswordHashAndCount::size);
    pos = std::max<int64_t>(0, pos);
    phc.read(mInputFile, pos);
    ++nReads;
    if (hash > phc.hash)
    {
      lo = pos + std::streamoff(PasswordHashAndCount::size);
    }
    else if (hash < phc.hash)
    {
      hi = pos - std::streamoff(PasswordHashAndCount::size);
    }
    else
    {
      safe_assign(readCount, nReads);
      return phc;
    }
  }
  phc.count = 0;
  safe_assign(readCount, nReads);
  return phc;
}

PasswordHashAndCount PasswordInspector::smart_binsearch(const Hash &hash, int *readCount)
{
  static constexpr float MaxUInt64 = float(std::numeric_limits<uint64_t>::max());
  int nReads = 0;
  static constexpr int64_t OffsetMultiplicator = 2;
  std::streamoff potentialHitIdx = std::llround(float(mFileSize) * float(hash.quad.upper) / MaxUInt64);
  potentialHitIdx -= potentialHitIdx % (std::streamoff)PasswordHashAndCount::size;
  std::streamoff offset = std::max<std::streamoff>(std::streamoff(mFileSize >> 12), (std::streamoff)PasswordHashAndCount::size);
  offset -= offset % (std::streamoff)PasswordHashAndCount::size;
  std::streamoff lo = std::max<std::streamoff>(0, potentialHitIdx - offset);
  std::streamoff hi = std::min<std::streamoff>(mFileSize - (std::streamoff)PasswordHashAndCount::size, potentialHitIdx + offset);
  bool ok = false;
  Hash h0;
  ok = h0.read(mInputFile, lo);
  ++nReads;
  int64_t loOffset = offset;
  while (hash < h0 && lo >= loOffset)
  {
    lo -= loOffset;
    h0.read(mInputFile, lo);
    ++nReads;
    loOffset *= OffsetMultiplicator;
  }
  Hash h1;
  ok = h1.read(mInputFile, hi);
  ++nReads;
  int64_t hiOffset = offset;
  while (hash > h1 && hi <= mFileSize - hiOffset - int64_t(PasswordHashAndCount::size))
  {
    hi += hiOffset;
    h1.read(mInputFile, hi);
    ++nReads;
    hiOffset *= OffsetMultiplicator;
  }
  int nBinSearchReads = 0;
  const PasswordHashAndCount &phc = binsearch(hash, &nBinSearchReads);
  safe_assign(readCount, nReads + nBinSearchReads);
  return phc;
}

PasswordHashAndCount PasswordInspector::lookup(const std::string &pwd)
{
  return binsearch(pwned::Hash(pwd));
}

std::size_t PasswordInspector::size() const
{
  return (std::size_t)mFileSize / (std::size_t)PasswordHashAndCount::size;
}
} // namespace pwned
