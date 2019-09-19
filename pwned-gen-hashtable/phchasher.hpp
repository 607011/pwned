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

#ifndef __phchasher_hpp__
#define __phchasher_hpp__

#include <cstdint>

#include <pwned-lib/passwordhashandcount.hpp>

class PHCHasher
{
public:
  static constexpr uint64_t FNV_offset_basis = 0xcbf29ce484222325ULL;
  static constexpr uint64_t FNV_prime = 0x100000001b3ULL;

  // optimized for 16 byte long inputs
  static inline uint64_t MurmurHash64A(const uint8_t *const key, const uint64_t seed)
  {
    static constexpr uint64_t m = 0xc6a4a7935bd1e995ULL;
    static constexpr int r = 47;
    uint64_t h = seed ^ (pwned::Hash::size * m);
    const uint64_t *data = reinterpret_cast<const uint64_t *>(key);
    uint64_t k;
    // 1st uint64
    k = data[0];
    k *= m;
    k ^= k >> r;
    k *= m;
    h ^= k;
    h *= m;
    // 2nd uint64
    k = data[1];
    k *= m;
    k ^= k >> r;
    k *= m;
    h ^= k;
    h *= m;
    //
    h ^= h >> r;
    h *= m;
    h ^= h >> r;
    return h;
  }

  static inline uint64_t FNV1a(const uint8_t *const data, const uint64_t seed)
  {
    uint64_t hash = FNV_offset_basis;
    for (int i = 0; i < pwned::Hash::size; ++i)
    {
      hash ^= static_cast<uint64_t>(data[i]);
      hash *= FNV_prime;
    }
    hash ^= seed;
    return hash;
  }

  uint64_t operator()(pwned::PasswordHashAndCount key, uint64_t seed = 0) const
  {
    return MurmurHash64A(key.hash.data, seed);
  }
};

#endif // __phchasher_hpp__
