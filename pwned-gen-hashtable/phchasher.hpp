#ifndef __phchasher_hpp__
#define __phchasher_hpp__

#include <cstdint>

#include <pwned-lib/passwordhashandcount.hpp>

class PHCHasher
{
public:
  static constexpr uint64_t FNV_offset_basis = 0xcbf29ce484222325;
  static constexpr uint64_t FNV_prime = 0x100000001b3;
  static constexpr int DataSize = sizeof(uint64_t);
  static uint64_t hashWithSeed(uint64_t key, uint64_t seed)
  {
    uint64_t hash = FNV_offset_basis;
    for (int i = 0; i < DataSize; ++i)
    {
      hash *= FNV_prime;
      hash ^= key & 0xff;
      key >>= 8;
    }
    hash ^= seed;
    return hash;
  }
  uint64_t operator()(pwned::PasswordHashAndCount key, uint64_t seed = 0) const
  {
    const uint64_t s0 = hashWithSeed(key.hash.upper, 0xAAAAAAAA55555555ULL);
    uint64_t s1 = hashWithSeed(key.hash.lower, 0x33333333CCCCCCCCULL);
    s1 ^= s1 << 23;
    return (s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26)) + s0;
  }
};

#endif // __phchasher_hpp__
