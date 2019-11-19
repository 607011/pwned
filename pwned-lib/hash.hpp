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

#ifndef __hash_hpp__
#define __hash_hpp__

#include <ostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <openssl/md5.h>

#if defined(WIN32)
#include <WinSock2.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#define ntohll(x) be64toh(x)
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/endian.h>
#define ntohll(x) be64toh(x)
#elif defined(__APPLE__)
#include <sys/_endian.h>
#elif defined(__OpenBSD__)
#include <sys/types.h>
#define ntohll(x) betoh64(x)
#endif

namespace pwned
{

struct Hash
{
  static constexpr int size = MD5_DIGEST_LENGTH;
  union {
    uint8_t data[size];
    struct
    {
      uint64_t upper;
      uint64_t lower;
    } quad;
  };
  bool isValid;
  Hash();
  Hash(const Hash &);
  explicit Hash(const std::string &pwd);
  Hash(uint64_t upper, uint64_t lower);

  inline void toHostByteOrder()
  {
    quad.upper = ntohll(quad.upper);
    quad.lower = ntohll(quad.lower);
  }

  inline bool read(std::istream &f)
  {
    f.read((char *)data, Hash::size);
    return f.gcount() == Hash::size;
  }

  inline bool read(std::istream &f, uint64_t pos)
  {
    f.seekg(pos);
    return read(f);
  }

  static Hash fromHex(const std::string &seq);
  std::string toString(bool uppercase = false) const;

  inline Hash &operator=(const Hash &rhs)
  {
    quad.upper = rhs.quad.upper;
    quad.lower = rhs.quad.lower;
    return *this;
  }
};

inline bool operator==(const Hash &lhs, const Hash &rhs)
{
  return lhs.quad.upper == rhs.quad.upper && lhs.quad.lower == rhs.quad.lower && lhs.isValid == rhs.isValid;
}

inline bool operator!=(const Hash &lhs, const Hash &rhs)
{
  return lhs.quad.upper != rhs.quad.upper || lhs.quad.lower != rhs.quad.lower ||  lhs.isValid == rhs.isValid;
}

inline bool operator<(const Hash &lhs, const Hash &rhs)
{
  if (lhs.quad.upper == rhs.quad.upper)
  {
    return lhs.quad.lower < rhs.quad.lower;
  }
  return lhs.quad.upper < rhs.quad.upper;
}

inline bool operator<=(const Hash &lhs, const Hash &rhs)
{
  return lhs == rhs || lhs < rhs;
}

inline bool operator>(const Hash &lhs, const Hash &rhs)
{
  if (lhs.quad.upper == rhs.quad.upper)
  {
    return lhs.quad.lower > rhs.quad.lower;
  }
  return lhs.quad.upper > rhs.quad.upper;
}

inline bool operator>=(const Hash &lhs, const Hash &rhs)
{
  return lhs == rhs || lhs > rhs;
}

std::ostream &operator<<(std::ostream &os, Hash const &h);

struct HashLess
{
  inline bool operator()(const Hash &lhs, const Hash &rhs) const
  {
    return lhs < rhs;
  }
};

} // namespace pwned

#endif // __hash_hpp__
