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
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstdint>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include <pwned-lib/passwordhashandcount.hpp>
#include <pwned-lib/util.hpp>
#include <pwned-lib/passwordinspector.hpp>


namespace po = boost::program_options;
namespace fs = boost::filesystem;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned indexer 1.0-RC - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`index --warranty'." << std::endl
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
  constexpr unsigned int DefaultBits = 24;
  std::string inputFilename;
  std::string outputFilename;
  unsigned int bits = DefaultBits;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set user:pass input file")
  ("output,O", po::value<std::string>(&outputFilename), "set index file")
  ("bits,B", po::value<unsigned int>(&bits)->default_value(DefaultBits), "set bit count of index key")
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

  if (inputFilename.empty())
  {
    std::cerr << "ERROR: input filename not given." << std::endl;
    usage();
    return EXIT_FAILURE;
  }
  if (outputFilename.empty())
  {
    std::cerr << "ERROR: output filename not given." << std::endl;
    usage();
    return EXIT_FAILURE;
  }

  const unsigned int shift = static_cast<unsigned int>(sizeof(pwned::index_key_t) * 8 - bits);
  const pwned::index_key_t maxidx = static_cast<pwned::index_key_t>(1) + (std::numeric_limits<pwned::index_key_t>::max() >> shift);

  std::cout << "Scanning ..." << std::endl;
  std::ifstream input(inputFilename, std::ios::binary);
  pwned::PasswordHashAndCount phc;
  pwned::index_key_t *indexes = new pwned::index_key_t[maxidx];
  memset(indexes, 0xff, maxidx * sizeof(pwned::index_key_t));
  phc.read(input);
  pwned::index_key_t lastIdx = static_cast<pwned::index_key_t>(phc.hash.quad.upper >> shift);
  *(indexes + lastIdx) = 0;
  pwned::index_key_t idx = 0;
  uint64_t pos = 0;
  while (!input.eof())
  {
    phc.read(input);
    idx = static_cast<pwned::index_key_t>(phc.hash.quad.upper >> shift);
    if (idx > lastIdx)
    {
      pos = static_cast<uint64_t>(input.tellg()) - pwned::PasswordHashAndCount::size;
      *(indexes + idx) = pos;
      std::cout << "\rMSB 0x" << std::hex << idx << " @ " << std::dec << pos << std::flush;
      lastIdx = idx;
    }
  }
  *(indexes + idx) = pos;
  input.close();

  std::cout << std::endl
            << "Writing ... " << std::flush;
  std::ofstream output(outputFilename, std::ios::trunc | std::ios::binary);
  output.write((const char *)indexes, maxidx * sizeof(pwned::index_key_t));
  output.close();
  delete[] indexes;
  std::cout << "Ready." << std::endl
            << std::endl;

  return EXIT_SUCCESS;
}
