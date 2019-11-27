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

#ifndef __passwordhashandcount_hpp__
#define __passwordhashandcount_hpp__

#include <fstream>
#include <cstdint>

#include "hash.hpp"

namespace pwned
{

class PasswordHashAndCount
{
public:
  static constexpr uint64_t size = uint64_t(Hash::size) + sizeof(uint32_t);
  Hash hash;
  uint32_t count;

  PasswordHashAndCount()
      : count(0)
  {
  }

  PasswordHashAndCount(Hash hash, uint32_t count)
      : hash(hash), count(count)
  {
  }

  PasswordHashAndCount(const PasswordHashAndCount &o)
      : hash(o.hash), count(o.count)
  {
  }

  inline bool read(std::istream &f)
  {
    f.read((char *)hash.data, Hash::size);
    if (f.gcount() != Hash::size)
      return false;
    f.read((char *)&count, sizeof(count));
    return f.gcount() == sizeof(count);
  }

  inline bool read(std::istream &f, std::streamoff pos)
  {
    f.seekg(pos);
    return read(f);
  }

  inline void dump(std::ofstream &f) const
  {
    f.write((char *)hash.data, Hash::size);
    f.write((char *)&count, sizeof(count));
  }
};

inline bool operator==(const PasswordHashAndCount &lhs, const PasswordHashAndCount &rhs)
{
  return lhs.hash == rhs.hash;
}

struct PasswordHashAndCountLess
{
  inline bool operator()(const pwned::PasswordHashAndCount &lhs, const pwned::PasswordHashAndCount &rhs) const
  {
    return lhs.hash < rhs.hash;
  }
};

typedef PasswordHashAndCount PHC;

} // namespace pwned

#endif // __passwordhashandcount_hpp__
