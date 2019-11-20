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
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <vector>
#include <chrono>
#include <string>
#include <cstring>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/asio/post.hpp>
#include <boost/bind/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/multiprecision/miller_rabin.hpp>

#include "pwned-lib/hash.hpp"
#include "pwned-lib/passwordhashandcount.hpp"
#include "phchasher.hpp"

namespace fs = boost::filesystem;
namespace mp = boost::multiprecision;

static constexpr std::chrono::milliseconds ProgressInterval{33};

struct ProgressStats
{
  uint64_t nCollisions;
  uint64_t nChecked;
  uint64_t nEntries;
  pwned::Hash currentHash;
};

void progress(boost::asio::steady_timer *t, ProgressStats *stats)
{
  const size_t BufSize = 20;
  char pctBuf[BufSize];
  const double pct = (stats->nEntries > 0) ? 1e2 * double(stats->nChecked) / double(stats->nEntries) : 0;
  std::snprintf(pctBuf, BufSize, "%.1f%%", pct);
  std::cout << "\r" << stats->currentHash << " " << pctBuf
            << " (" << stats->nCollisions << " collisions"
            << " in " << stats->nChecked << " entries, "
            << (1e2 * double(stats->nCollisions) / double(stats->nChecked)) << "%)"
            << std::flush;
  if (stats->nChecked < stats->nEntries)
  {
    t->expires_at(t->expiry() + ProgressInterval);
    t->async_wait(boost::bind(progress, t, stats));
  }
}

int main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;
  ProgressStats stats;
  // const std::string inputFilename = "../../pwned-lib/test/testset-10000-existent-collection1+2+3+4+5.md5";
  const std::string inputFilename = "/home/ola/pwned-data/collection1+2+3+4+5.md5";
  stats.nEntries = fs::file_size(inputFilename) / pwned::PHC::size;
  std::ifstream inputFile(inputFilename, std::ios::binary);
  int nBits = 24;
  uint64_t modulus = 1ULL << nBits;
  const uint64_t minMod = modulus / 2;
  while (--modulus > minMod && !mp::miller_rabin_test(modulus, 25));
  std::cout << "modulus = " << modulus << std::endl;

  stats.nCollisions = 0;
  stats.nChecked = 0;

  boost::asio::io_context ioc{2};
  boost::asio::steady_timer timer(ioc, ProgressInterval);
  timer.async_wait(boost::bind(progress, &timer, &stats));

  boost::asio::post([&stats, &inputFile, modulus]() {
    pwned::PHC phc;
    pwned::PHCHasher hasher;
    std::vector<bool> keys(modulus, false);
    while (!inputFile.eof())
    {
      ++stats.nChecked;
      phc.read(inputFile);
      stats.currentHash = phc.hash;
      const uint64_t key = hasher(phc) % modulus;
      if (keys[key])
      {
        ++stats.nCollisions;
      }
      else
      {
        keys[key] = true;
      }
    }
  });

  ioc.run();

  std::cout << stats.nCollisions << " collisions (" << (1e2 * double(stats.nCollisions) / double(stats.nChecked)) << "%)" << std::endl;
  return EXIT_SUCCESS;
}