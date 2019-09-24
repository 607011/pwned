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
#include <iomanip>
#include <bitset>
#include <fstream>
#include <string>
#include <chrono>
#include <vector>
#include <random>
#include <strings.h>
#include <limits.h>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/dynamic_bitset.hpp>

#include <pwned-lib/passwordinspector.hpp>
#include <pwned-lib/phchasher.hpp>

#include "phcfile.hpp"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned mphf 0.1 - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-mphf-cli --warranty'." << std::endl
            << "This is free software, and you are welcome to redistribute it" << std::endl
            << "under certain conditions; see https://www.gnu.org/licenses/gpl-3.0.en.html" << std::endl
            << "for details." << std::endl
            << std::endl;
}

void warranty()
{
  std::cout << "Warranty info:" << std::endl
            << std::endl
            << "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION." << std::endl
            << std::endl
            << "IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES." << std::endl
            << std::endl;
}

void usage()
{
  std::cout << desc << std::endl;
}

int main(int argc, const char *argv[])
{
  std::string inputFilename;
  std::string mphfFilename;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set MD5:count input file")
  ("mphf,H", po::value<std::string>(&mphfFilename), "set MPHF file")
  ("warranty", "display warranty information")
  ("license", "display license information");
  po::variables_map vm;
  try
  {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  }
  catch (po::error &e)
  {
    std::cerr << "ERROR: " << e.what() << std::endl
              << std::endl;
    return EXIT_FAILURE;
  }
  po::notify(vm);
  if (inputFilename.empty())
  {
    std::cerr << "ERROR: input file not given." << std::endl;
    usage();
    return EXIT_FAILURE;
  }

  uint64_t inputSize = fs::file_size(inputFilename);
  uint64_t nKeys = inputSize / pwned::PasswordHashAndCount::size;
  int bitsNeeded = fls(nKeys) - 1;
  uint64_t hashTableSize = nKeys * bitsNeeded / 8;
  std::cout << "keys found: " << std::bitset<64>(nKeys) << " (" << nKeys << ")"  << std::endl;
  std::cout << "fls(nKeys): " << std::bitset<64>(1 << bitsNeeded) << " (" << bitsNeeded << ")" << std::endl;
  std::cout << "hash table size: " << (hashTableSize / 1024 / 1024) << " MByte" << std::endl;

  boost::dynamic_bitset<> slots(nKeys);

  std::mt19937_64 gen;
  gen.seed(31337);

  PHCFile input(inputFilename);
  uint64_t i = 0;
  uint64_t nCollisions = 0;
  for (const auto &phc : input)
  {
    const uint64_t idx = pwned::PHCHasher::MurmurHash64A(phc.hash, 0) % nKeys;
    // const uint64_t idx = pwned::PHCHasher::FNV1a(phc.hash, 0) % nKeys;
    if (slots.test(idx))
    {
      ++nCollisions;
    }
    else
    {
      slots.set(idx);
    }
    ++i;
  }
  std::cout << "collisions: " << nCollisions << " (" << (100.0 * double(nCollisions) / double(nKeys)) << "%)" << std::endl;

  return EXIT_SUCCESS;
}
