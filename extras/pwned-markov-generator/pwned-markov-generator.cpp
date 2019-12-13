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
#include <cstdint>
#include <cstdlib>
#include <string>
#include <fstream>
#include <exception>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/locale/encoding_utf.hpp>

#include <pwned-lib/userpasswordreader.hpp>
#include <pwned-lib/markovnode.hpp>
#include <pwned-lib/markovchain.hpp>

namespace markov = pwned::markov;
namespace po = boost::program_options;
namespace fs = boost::filesystem;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned markov generator 1.0.0-BETA - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-markov-generator --warranty`." << std::endl
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

struct Counter { int level = 0; };

void validate(boost::any &v, std::vector<std::string> const &xs, Counter*, long)
{
  if (v.empty())
  {
    v = Counter{1};
  }
  else
  {
    ++boost::any_cast<Counter&>(v).level;
  }
}

int main(int argc, char* argv[])
{
  hello();
  uint64_t outputEvery;
  std::string inputFilename;
  std::string outputFilename;
  Counter verbosity;
  desc.add_options()
  ("help,?", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set password file")
  ("output,O", po::value<std::string>(&outputFilename), "set markov file")
  ("verbose,v", po::value(&verbosity)->zero_tokens(), "increase verbosity")
  ("output-every,N", po::value(&outputEvery)->default_value(100'000), "output statistics every n-th password")
  ("warranty", "display warranty information")
  ("license", "display license information");
  po::variables_map vm;
  try
  {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  }
  catch (const po::error &e)
  {
    std::cerr << "ERROR: " << e.what() << std::endl
              << std::endl;
    usage();
    return EXIT_FAILURE;
  }
  po::notify(vm);

  if (vm.count("help") > 0)
  {
    usage();
    return EXIT_SUCCESS;
  }

  if (inputFilename.empty())
  {
    std::cerr << "ERROR: input file not given." << std::endl;
    usage();
    return EXIT_FAILURE;
  }

  if (outputFilename.empty())
  {
    std::cerr << "ERROR: output file not given." << std::endl;
    usage();
    return EXIT_FAILURE;
  }

  std::ifstream inputFile(inputFilename);
  if (!inputFile.is_open())
  {
    std::cerr << "Cannot read from '" << inputFilename << "'." << std::endl;
  }
  std::ofstream outputFile(outputFilename, std::ios::trunc | std::ios::binary);
  if (!outputFile.is_open())
  {
    std::cerr << "Cannot write to '" << outputFilename << "'." << std::endl;
  }
  std::vector<pwned::UserPasswordReaderOptions> readerOptions{pwned::UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords};
  pwned::UserPasswordReader reader(inputFile, readerOptions);
  using symbol_type = wchar_t;
  using prob_value_type = double;
  uint64_t n = 0;
  markov::Chain<symbol_type, prob_value_type> chain;
  const uint64_t fileSize = fs::file_size(inputFilename);
  if (verbosity.level > 0)
  {
    std::cout << "Reading from '" << inputFilename << "' (" << fileSize << " bytes) ..." << std::endl;
  }
  while (!reader.eof())
  {
    const std::string &pwd = reader.nextPassword();
    const std::basic_string<symbol_type> &s32 = boost::locale::conv::utf_to_utf<symbol_type>(pwd.c_str(), pwd.c_str() + pwd.size());
    if (!s32.empty()) {
      chain.addFirst(s32.at(0));
      if (s32.size() > 1)
      {
        for (std::size_t i = 0; i < s32.size() - 1; ++i)
        {
          chain.addPair(s32.at(i), s32.at(i+1));
        }
        if (verbosity.level > 0 && ((n % outputEvery) == 0))
        {
          constexpr std::size_t BufSize = 8;
          char buf[BufSize];
          snprintf(buf, BufSize, "%6.2f", (1e2 * (double)inputFile.tellg() / (double)fileSize));
          std::cout << '\r' << buf << "% \x1b[1;36m" << pwd << "\x1b[0m\x1b[K" << std::flush;
        }
        ++n;
      }
    }
  }
  chain.update();
  if (verbosity.level > 0)
  {
    std::cout << "\rWriting to '" << outputFilename << "' ..." << std::endl;
  }
  chain.writeBinary(outputFile);
  outputFile.close();
  return EXIT_SUCCESS;
}
