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
#include <fstream>
#include <iterator>
#include <string>
#include <chrono>
#include <thread>
#include <cstdint>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include <pwned-lib/passwordhashandcount.hpp>
#include <pwned-lib/passwordinspector.hpp>
#include <pwned-lib/phchasher.hpp>
#include <pwned-lib/util.hpp>

#include <BBHash/BooPHF.h>

#include "phcfileiterator.hpp"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

static constexpr double DefaultGamma = 2;
static constexpr unsigned int DefaultThreadCount = 4;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned MPHF table generator 0.1 - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-gen-hashtable --warranty'." << std::endl
            << "This is free software, and you are welcome to redistribute it" << std::endl
            << "under certain conditions; see https://www.gnu.org/licenses/gpl-3.0.en.html" << std::endl
            << "for details." << std::endl
            << std::endl;
}

void warranty()
{
  std::cout << "Warranty info:"
            << std::endl
            << std::endl
            << "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION."
            << std::endl
            << std::endl
            << "IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES."
            << std::endl
            << std::endl;
}

void usage()
{
  std::cout << desc << std::endl;
}

int main(int argc, const char *argv[])
{
  hello();
  std::string inputFilename;
  std::string outputFilename;
  double gamma = DefaultGamma;
  unsigned int threadCount = std::thread::hardware_concurrency();
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set user:pass input file")
  ("output,O", po::value<std::string>(&outputFilename), "set hashtable file")
  ("gamma,G", po::value<double>(&gamma)->default_value(DefaultGamma), "gamma (typically 1...5)")
  ("threads,T", po::value<unsigned int>(&threadCount)->default_value(threadCount), "use so many threads")
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
    usage();
  }
  po::notify(vm);
  if (vm.count("help"))
  {
    usage();
    return EXIT_SUCCESS;
  }
  if (vm.count("warranty"))
  {
    warranty();
    return EXIT_SUCCESS;
  }
  if (vm.count("license"))
  {
    license();
    return EXIT_SUCCESS;
  }
  if (inputFilename.empty() || outputFilename.empty())
  {
    usage();
    return EXIT_SUCCESS;
  }
  if (threadCount == 0)
  {
    threadCount = DefaultThreadCount;
  }
  if (gamma < 1)
  {
    gamma = DefaultGamma;
  }

  const uint64_t inputSize = fs::file_size(inputFilename);
  const uint64_t phcCount = inputSize / pwned::PasswordHashAndCount::size;
  std::cout << "Input file:  " << inputFilename << " with " << phcCount << " hashes" << std::endl
            << "Output file: " << outputFilename << std::endl
            << std::endl;

  std::cout << "Generating MPHF table in " << threadCount << " threads (gamma = " << gamma << ")... " << std::endl;
  auto t0 = std::chrono::high_resolution_clock::now();
  PHCFile phcs(inputFilename);
  if (!phcs.is_open())
  {
    std::cerr << "ERROR: Cannot open input file '" << inputFilename << "'." << std::endl;
    return EXIT_FAILURE;
  }
  pwned::MPHF *phf = new pwned::MPHF(phcCount, phcs, threadCount, gamma);
  auto t1 = std::chrono::high_resolution_clock::now();
  auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0);
  std::cout << "Ready. (total time: " << pwned::readableTime(time_span.count()) << ")" << std::endl;

  std::ofstream outputFile(outputFilename, std::ios::trunc | std::ios::binary);
  if (!outputFile.is_open())
  {
    std::cerr << "ERROR: Cannot open output file '" << outputFilename << "'." << std::endl;
    return EXIT_FAILURE;
  }
  std::cout << "Writing MPHF table ... " << std::flush;
  phf->save(outputFile);
  std::cout << "Finished." << std::endl
            << std::endl;
  delete phf;
  return EXIT_SUCCESS;
}
