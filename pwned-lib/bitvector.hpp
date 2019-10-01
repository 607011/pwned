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

#ifndef __bitvector_hpp__
#define __bitvector_hpp__

#include <limits>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace pwned {

template <typename value_type = uint64_t, element_type = uint64_t>
class BitVector
{
public:
  BitVector()
      : bitsPerEntry(0)
      , size(0)
      , mask(0)
      , data(nullptr)
  {
  }

  BitVector(unsigned int bitsPerEntry, uint64_t size)
      : bitsPerEntry(bitsPerEntry)
      , size(size)
  {
    if (bitsPerEntry > sizeof(value_type) * 8)
    {
      throw "Illegal number of bits per entry";
    }
    data = new value_type[size * bitsPerEntry / 8 / sizeof(value_type)];
    mask = (1 << bitsPerEntry) - 1;
  }

  BitVector(const BitVector &other)
      : bitsPerEntry(other.bitsPerEntry)
      , size(other.size)
      , mask(other.mask)
  {
    data = new value_type[size * bitsPerEntry / 8 / sizeof(value_type)];
    memcpy(data, other.data, size * bitsPerEntry / 8);
  }

  ~BitVector()
  {
    if (data != nullptr)
    {
      delete[] data;
    }
  }

  void save(std::ostream &out)
  {
    if (size > 0 && data != nullptr)
    {
      out.write(reinterpret_cast<const char *>(&bitsPerEntry), sizeof(bitsPerEntry));
      out.write(reinterpret_cast<const char *>(&size), sizeof(size));
      for (uint64_t i = 0; i < size * bitsPerEntry / 8 / sizeof(value_type); ++i)
      {
        out.write(reinterpret_cast<const char *>(data[i]), sizeof(value_type));
      }
    }
  }

  void load(std::istream &in)
  {
    in.read(reinterpret_cast<char*>(&bitsPerEntry), sizeof(bitsPerEntry));
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (data != nullptr)
    {
      delete[] data;
    }
    const uint64_t N = size * bitsPerEntry / 8 / sizeof(value_type);
    data = new value_type[N];
    mask = (1 << bitsPerEntry) - 1;
    for (uint64_t i = 0; i < N; ++i)
    {
      in.read(reinterpret_cast<char*>(data[i]), sizeof(value_type));
    }
  }

  value_type get(uint64_t pos) const
  {
    // no bounds checking to improve performance
    const uint64_t bitIdx = pos * bitsPerEntry;
    const unsigned int bitRem = static_cast<unsigned int>(bitIdx % sizeof(value_type));
    const uint64_t idx = bitIdx / sizeof(value_type) / 8;
    value_type val = 0;
    if (bitRem < bitsPerEntry)
    {
      const unsigned int shift = sizeof(value_type) * 8 - bitsPerEntry - bitRem;
      val = data[idx] >> shift;
    }
    else
    {
      const unsigned int shift1 = sizeof(value_type) * 8 - bitRem;
      const unsigned int shift2 = sizeof(value_type) * 8 - bitsPerEntry - bitRem - shift1;
      val = (data[idx] << shift1) | (data[idx+1] >> shift2);
    }
    return val & mask;
  }

  value_type operator[] (uint64_t pos) const
  {
    return get(pos);
  }

  void set(uint64_t pos, value_type val)
  {
    const uint64_t bitIdx = pos * bitsPerEntry;
    const uint64_t bitRem = bitIdx % sizeof(value_type);
    const uint64_t idx = bitIdx / sizeof(value_type) / 8;
    if (bitRem < bitsPerEntry)
    {
      const int shift = sizeof(value_type) * 8 - bitsPerEntry - bitRem;
      const value_type orig = data[idx];
      const value_type newVal = val << shift;
      const value_type invMask = 0;
      data[idx] = (orig & invMask) | newVal;
    }

  }

private:
  unsigned int bitsPerEntry;
  uint64_t size;
  element_type mask;
  element_type *data;
  static const char MAGIC[8];
};

} // namespace pwned

#endif // __bitvector_hpp__
