#include <iostream>
#include <iomanip>
#include <chrono>

inline uint64_t bswap(uint64_t a)
{
  return (((a & 0xff00000000000000ull) >> 56) |
          ((a & 0x00ff000000000000ull) >> 40) |
          ((a & 0x0000ff0000000000ull) >> 24) |
          ((a & 0x000000ff00000000ull) >> 8) |
          ((a & 0x00000000ff000000ull) << 8) |
          ((a & 0x0000000000ff0000ull) << 24) |
          ((a & 0x000000000000ff00ull) << 40) |
          ((a & 0x00000000000000ffull) << 56));
}

int main(int argc, char *argv[])
{
  static constexpr uint64_t N_ITERS = 10000000000ULL;
  std::cout << "DIY bswap(): " << std::flush;
  auto t0 = std::chrono::high_resolution_clock::now();
  for (uint64_t i = 0; i < N_ITERS; ++i) {
    volatile uint64_t a = bswap(i);
  }
  std::cout << std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - t0).count() << std::endl;

#if defined(_MSC_VER)
  std::cout << "_byteswap_uint64(): " << std::flush;
  for (uint64_t i = 0; i < N_ITERS; ++i) {
    volatile uint64_t a = _byteswap_uint64(i);
  }
#endif

#if defined(__linux__)
#include <byteswap.h>
  std::cout << "Linux bswap_64: " << std::flush;
  for (uint64_t i = 0; i < N_ITERS; ++i) {
    volatile uint64_t a = bswap_64(i);
  }
#endif

#if (defined(__clang__) && __has_builtin(__builtin_bswap32) && __has_builtin(__builtin_bswap64)) \
  || (defined(__GNUC__ ) && \
  (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)))
#include <cstdlib>
  std::cout << "__builtin_bswap64(): " << std::flush;
  t0 = std::chrono::high_resolution_clock::now();
  for (uint64_t i = 0; i < N_ITERS; ++i) {
    volatile uint64_t a = __builtin_bswap64(i);
  }
  std::cout << std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - t0).count() << std::endl;
#endif

  std::cout << std::endl;
  return 0;
}