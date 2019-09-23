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

#include <BBHash/BooPHF.h>

#include "passwordhashandcount.hpp"

namespace pwned {

class PHCHasher
{
public:
  // TODO: select one of MurmurHash64A and FNV1a

  // optimized for 16 byte long inputs
  static inline uint64_t MurmurHash64A(const uint64_t a, const uint64_t b, const uint64_t seed)
  {
    static constexpr uint64_t M = 0xc6a4a7935bd1e995ULL;
    static constexpr int R = 47;
    uint64_t h = seed ^ (pwned::Hash::size * M);
    uint64_t k;

    // 1st uint64
    k = a;
    k *= M;
    k ^= k >> R;
    k *= M;
    h ^= k;
    h *= M;

    // 2nd uint64
    k = b;
    k *= M;
    k ^= k >> R;
    k *= M;
    h ^= k;
    h *= M;

    h ^= h >> R;
    h *= M;
    h ^= h >> R;
    return h;
  }

  static inline uint64_t FNV1a(const uint8_t *const data, const uint64_t seed)
  {
    static constexpr uint64_t FNV_offset_basis = 0xcbf29ce484222325ULL;
    static constexpr uint64_t FNV_prime = 0x100000001b3ULL;
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
    return MurmurHash64A(key.hash.upper, key.hash.lower, seed);
    // return FNV1a(key.hash.data, seed);
  }
};

typedef boomphf::mphf<PasswordHashAndCount, PHCHasher> MPHF;

} // namespace pwned

#endif // __phchasher_hpp__
