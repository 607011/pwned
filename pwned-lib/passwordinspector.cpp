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

#ifndef NO_POPCNT
#include <popcntintrin.h>
#endif

#include <boost/filesystem.hpp>

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

#if defined(NO_POPCNT)
inline unsigned int popcount64(uint64_t x)
{
  constexpr uint64_t m1 = 0x5555555555555555ULL;
  constexpr uint64_t m2 = 0x3333333333333333ULL;
  constexpr uint64_t m4 = 0x0f0f0f0f0f0f0f0fULL;
  constexpr uint64_t h01 = 0x0101010101010101ULL;
  x -= (x >> 1) & m1;
  x = (x & m2) + ((x >> 2) & m2);
  x = (x + (x >> 4)) & m4;
  return static_cast<unsigned int>((x * h01) >> 56);
}
#else
#define popcount64(x) static_cast<unsigned int>(_mm_popcnt_u64(x))
#endif // NO_POPCNT

static inline PasswordHashAndCount _binsearch(std::ifstream &inputFile, const Hash &hash, int64_t lo, int64_t hi, int *readCount)
{
  int nReads = 0;
  PasswordHashAndCount phc;
  while (lo <= hi)
  {
    int64_t pos = (lo + hi) / 2;
    pos -= pos % PasswordHashAndCount::size;
    pos = std::max<int64_t>(0, pos);
    phc.read(inputFile, pos);
    ++nReads;
    if (hash > phc.hash)
    {
      lo = pos + PasswordHashAndCount::size;
    }
    else if (hash < phc.hash)
    {
      hi = pos - PasswordHashAndCount::size;
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

PasswordInspector::PasswordInspector()
    : size(0)
    , shift(0)
{
}

PasswordInspector::PasswordInspector(const std::string &inputFilename)
{
  open(inputFilename);
}

PasswordInspector::PasswordInspector(const std::string &inputFilename, const std::string &indexFilename)
{
  openWithIndex(inputFilename, indexFilename);
}

PasswordInspector::~PasswordInspector() = default;

bool PasswordInspector::open(const std::string &filename)
{
  size = int64_t(fs::file_size(filename));
  inputFile.open(filename, std::ios::in | std::ios::binary);
  return inputFile.is_open();
}

bool PasswordInspector::openWithIndex(const std::string &inputFilename, const std::string &indexFilename)
{
  bool ok = open(inputFilename);
  if (!indexFilename.empty())
  {
    const uint64_t nKeys = static_cast<uint64_t>(fs::file_size(indexFilename)) / sizeof(index_key_t);
    shift = sizeof(index_key_t) * 8 - popcount64(nKeys - 1);
    indexFile.open(indexFilename, std::ios::in | std::ios::binary);
    ok = ok && indexFile.is_open();
  }
  return ok;
}

bool PasswordInspector::openWithMPHF(const std::string &inputFilename, const std::string &mphfFilename)
{
  bool ok = open(inputFilename);
  if (!mphfFilename.empty())
  {
    mphfFile.open(mphfFilename, std::ios::binary);
    if (mphfFile.is_open())
    {
      mphf.load(mphfFile);
      std::cout << "mphf.nbKeys() = " << mphf.nbKeys() << std::endl;
      std::cout << "mphf.totalBitSize() = " << mphf.totalBitSize() << std::endl;
    }
    else
    {
      ok = false;
    }
  }
  return ok;
}

PasswordHashAndCount PasswordInspector::mphfSearch(const Hash &hash, int *readCount)
{
  int nReads = 0;
  PasswordHashAndCount soughtPHC(hash, 0);
  PasswordHashAndCount phc;
  if (mphfFile.is_open())
  {
    const uint64_t idx = mphf.lookup(soughtPHC);
    // the index returned by lookup() is NOT the index into the original data
    if (idx != ULLONG_MAX)
    {
      phc.count = 1;
    }
  }
  safe_assign(readCount, nReads);
  return phc;
}

PasswordHashAndCount PasswordInspector::binSearch(const Hash &hash, int *readCount)
{
  int nReads = 0;
  int64_t lo = 0;
  int64_t hi = size;
  if (indexFile.is_open())
  {
    const uint64_t hashMSB = hash.upper >> shift;
    const uint64_t idx = hashMSB * sizeof(index_key_t);
    uint64_t loIdx = idx;
    do {
      indexFile.seekg(loIdx);
      indexFile.read(reinterpret_cast<char*>(&lo), sizeof(index_key_t));
      ++nReads;
      loIdx -= sizeof(index_key_t);
    }
    while (lo == std::numeric_limits<index_key_t>::max());
    uint64_t hiIdx = idx + sizeof(index_key_t);
    do {
      indexFile.seekg(hiIdx);
      indexFile.read(reinterpret_cast<char*>(&hi), sizeof(index_key_t));
      ++nReads;
      hiIdx += sizeof(index_key_t);
    }
    while (hi == std::numeric_limits<index_key_t>::max());
  }
  const PasswordHashAndCount &phc = _binsearch(inputFile, hash, lo, hi, &nReads);
  safe_assign(readCount, nReads + *readCount);
  return phc;
}

PasswordHashAndCount PasswordInspector::smartBinSearch(const Hash &hash, int *readCount)
{
  static constexpr double MaxUInt64 = double(std::numeric_limits<uint64_t>::max());
  int nReads = 0;
  static constexpr int64_t OffsetMultiplicator = 2;
  const double h128 = double(hash.upper) + double(hash.lower) / MaxUInt64;
  int64_t potentialHitIdx = int64_t(h128 / MaxUInt64 * double(size));
  potentialHitIdx -= potentialHitIdx % PasswordHashAndCount::size;
  // shifting 12 times leads to the empirically determined optimal offset
  int64_t offset = std::max<int64_t>(int64_t(size >> 12), PasswordHashAndCount::size);
  offset -= offset % PasswordHashAndCount::size;
  int64_t lo = std::max<int64_t>(0, potentialHitIdx - offset);
  int64_t hi = std::min<int64_t>(size - PasswordHashAndCount::size, potentialHitIdx + offset);
  bool ok = false;
  Hash h0;
  ok = h0.read(inputFile, lo);
  ++nReads;
  if (!ok)
  {
    throw("[PasswordInspector] Cannot read @ lo = " + std::to_string(lo));
  }
  int64_t loOffset = offset;
  while (hash < h0 && lo >= loOffset)
  {
    lo -= loOffset;
    h0.read(inputFile, lo);
    ++nReads;
    loOffset *= OffsetMultiplicator;
  }
  Hash h1;
  ok = h1.read(inputFile, hi);
  ++nReads;
  if (!ok)
  {
    throw("[PasswordInspector] Cannot read @ hi = " + std::to_string(hi));
  }
  int64_t hiOffset = offset;
  while (hash > h1 && hi <= size - hiOffset - PasswordHashAndCount::size)
  {
    hi += hiOffset;
    h1.read(inputFile, hi);
    ++nReads;
    hiOffset *= OffsetMultiplicator;
  }
  // sanity check
  if (!(h0 <= hash && hash <= h1))
  {
    throw("[PasswordInspector] Hash out of bounds: !(" + h0.toString() + " < " + hash.toString() + " < " + h1.toString() + ")");
  }
  const PasswordHashAndCount &phc = _binsearch(inputFile, hash, lo, hi, &nReads);
  safe_assign(readCount, nReads + *readCount);
  return phc;
}

PasswordHashAndCount PasswordInspector::lookup(const std::string &pwd)
{
  return binSearch(pwned::Hash(pwd));
}

} // namespace pwned
