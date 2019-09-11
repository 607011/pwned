/*
 Copyright © 2019 Oliver Lau <oliver@ersatzworld.net>

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

#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>

#include "hash.hpp"

namespace pwned
{

static inline int decodeHex(const char c)
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

Hash::Hash()
    : isValid(false)
{
}

Hash::Hash(const Hash &o)
    : upper(o.upper), lower(o.lower), isValid(o.isValid)
{
}

Hash::Hash(uint64_t upper, uint64_t lower)
    : upper(upper), lower(lower), isValid(true)
{
}

Hash::Hash(const std::string &pwd)
{
  MD5((const unsigned char *)pwd.c_str(), pwd.size(), data);
  toLittleEndian();
  isValid = true;
}

void Hash::toLittleEndian()
{
  // There's no need to optimize the following byte-swapping with calls
  // to functions like _byteswap_uint64() (MSC), __builtin_bswap64()
  // (clang, GCC) or bswap_64() (Linux), because modern compilers like
  // clang or g++ automatically convert the following lines to two bswapq
  // machine code instructions.
  upper = (((upper & 0xff00000000000000ull) >> 56) |
           ((upper & 0x00ff000000000000ull) >> 40) |
           ((upper & 0x0000ff0000000000ull) >> 24) |
           ((upper & 0x000000ff00000000ull) >> 8) |
           ((upper & 0x00000000ff000000ull) << 8) |
           ((upper & 0x0000000000ff0000ull) << 24) |
           ((upper & 0x000000000000ff00ull) << 40) |
           ((upper & 0x00000000000000ffull) << 56));
  lower = (((lower & 0xff00000000000000ull) >> 56) |
           ((lower & 0x00ff000000000000ull) >> 40) |
           ((lower & 0x0000ff0000000000ull) >> 24) |
           ((lower & 0x000000ff00000000ull) >> 8) |
           ((lower & 0x00000000ff000000ull) << 8) |
           ((lower & 0x0000000000ff0000ull) << 24) |
           ((lower & 0x000000000000ff00ull) << 40) |
           ((lower & 0x00000000000000ffull) << 56));
}

std::string Hash::toString() const
{
  std::ostringstream ss;
  ss << std::setw(16) << std::setfill('0') << std::hex << std::uppercase << upper << std::setw(16) << std::setfill('0') << std::uppercase << lower;
  return ss.str();
}

Hash Hash::fromHex(const std::string &seq)
{
  Hash hash;
  if (seq.size() == 2 * HashSize)
  {
    size_t j = 0;
    for (size_t i = 0; i < seq.size(); i += 2)
    {
      const int hi = decodeHex(seq.at(i));
      const int lo = decodeHex(seq.at(i + 1));
      if (hi >= 0 && lo >= 0)
      {
        const int b = (hi << 4) + lo;
        hash.data[j] = (uint8_t)b;
        ++j;
      }
      else
      {
        break;
      }
    }
    hash.isValid = j == HashSize;
  }
  return hash;
}

std::ostream &operator<<(std::ostream &os, Hash const &h)
{
  return os << h.toString();
}
} // namespace pwned
