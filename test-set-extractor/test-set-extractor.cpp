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
#include <string>
#include <cstdint>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/random/mersenne_twister.hpp>

#include <passwordhashandcount.hpp>
#include <passwordinspector.hpp>

namespace po = boost::program_options;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned lookup benchmark 1.0-RC - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`test-set-extractor --warranty'." << std::endl
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
  static constexpr int DefaultN = 20000;
  int N = DefaultN;
  bool onlyNonExistent = false;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set user:pass input file")
  ("output,O", po::value<std::string>(&outputFilename), "set user:pass test set file")
  ("num,N", po::value<int>(&N)->default_value(DefaultN), "number of data sets to extract")
  ("non-existent", po::bool_switch(&onlyNonExistent)->default_value(false), "select only non-existing hashes (or else only hashes contained in the input file will be selected)")
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

  const uint64_t size = boost::filesystem::file_size(inputFilename);
  const uint64_t offset = size / uint64_t(N);
  std::ifstream in(inputFilename, std::ios::binary);
  if (!in.is_open())
  {
    std::cerr << "Cannot open " << inputFilename << std::endl;
    return EXIT_FAILURE;
  }
  std::ofstream out(outputFilename, std::ios::binary | std::ios::trunc);
  if (!out.is_open())
  {
    std::cerr << "Cannot open " << outputFilename << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "Input file:  " << inputFilename << " (" << size << " bytes, offset = " << offset << ")" << std::endl
            << "Output file: " << outputFilename << std::endl;

  if (onlyNonExistent)
  {
    std::cout << "Selecting " << N << " non-existent hashes ... " << std::endl;
    boost::random::mt19937_64 gen;
    gen.seed(31337);
    pwned::PasswordInspector inspector(inputFilename);
    for (auto i = 0; i < N; ++i)
    {
      pwned::Hash hash(gen(), gen());
      pwned::PHC p = inspector.binsearch(hash);
      if (p.count == 0)
      {
        p.hash = hash;
        p.dump(out);
        std::cout << hash << " #" << i << std::endl;
      }
    }
  }
  else
  {
    std::cout << "Selecting " << N << " existent hashes ... " << std::endl;
    pwned::PHC phc;
    int i = 0;
    for (uint64_t pos = 0; pos < size && i < N; pos += offset)
    {
      const uint64_t idx = pos - pos % pwned::PHC::size;
      if (phc.read(in, idx))
      {
        std::cout << phc.hash << " @ " << idx << std::endl;
        phc.dump(out);
        ++i;
      }
    }
  }

  std::cout << std::endl
            << "Ready." << std::endl;
  return EXIT_SUCCESS;
}
