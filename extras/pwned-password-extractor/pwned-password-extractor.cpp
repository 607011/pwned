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
#include <cstdlib>

#include <boost/program_options.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#include <bzlib.h>

#include <pwned-lib/userpasswordreader.hpp>


namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace ba = boost::algorithm;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned password extractor 1.0-BETA - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-password-extractor --warranty`." << std::endl
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
  std::string srcDirectory;
  std::string outputFilename;
  std::vector<std::string> inputFilenames;
  bool compress;
  desc.add_options()
  ("help", "produce help message")
  ("source,S", po::value<std::string>(&srcDirectory), "set user:pass input directory")
  ("output,O", po::value<std::string>(&outputFilename), "set output file")
  ("compress,C", po::bool_switch(&compress), "compress output with BZ2")
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
  if (srcDirectory.empty() || outputFilename.empty())
  {
    usage();
    return EXIT_SUCCESS;
  }

  std::cout << "Scanning '" << srcDirectory << "' for files ... " << std::flush;
  fs::recursive_directory_iterator fileTreeIterator(srcDirectory);
  for (const auto &f : fileTreeIterator)
  {
    const std::string &filePath = f.path().string();
    if (fs::is_regular_file(f) && ba::ends_with(filePath, ".txt"))
    {
      inputFilenames.push_back(filePath);
    }
  }
  std::cout << std::endl;
  if (inputFilenames.empty())
  {
    std::cerr << "No files found in '" << srcDirectory << "'." << std::endl;
    return EXIT_FAILURE;
  }

  std::ofstream out;
  int bzError = BZ_OK;
  FILE *bz2File = nullptr;
  BZFILE *pBz = nullptr;
  if (compress)
  {
    outputFilename.append(".bz2");
    bz2File = fopen(outputFilename.c_str(), "wb+");
    if (bz2File == NULL)
    {
      std::cerr << "Cannot open '" << outputFilename << "' for writing." << std::endl;
      return EXIT_FAILURE;
    }
    pBz = BZ2_bzWriteOpen(&bzError, bz2File, 8, 0, 0);
    if (bzError != BZ_OK)
    {
      std::cerr << "Cannot create BZ2 writer for '" << outputFilename << "'." << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << "Compressing output file with BZ2." << std::endl;
  }
  else
  {
    out.open(outputFilename, std::ios::trunc | std::ios::binary);
    if (!out.is_open())
    {
      std::cerr << "Cannot open '" << outputFilename << "' for writing." << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << "Writing to UNCOMPRESSED output file." << std::endl;
  }

  std::cout << "Extracting passwords from ... " << std::endl;
  const std::vector<pwned::UserPasswordReaderOptions> readerOptions{pwned::UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords};
  for (const auto &inputFilename : inputFilenames)
  {
    std::ifstream in(inputFilename);
    if (!in.is_open())
    {
      std::cerr << "Cannot open " << inputFilename << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << inputFilename << std::flush;
    pwned::UserPasswordReader reader(in, readerOptions);
    while (!reader.eof())
    {
      const std::string &pwd = reader.nextPassword() + "\n";
      if (!pwd.empty())
      {
        if (compress)
        {
          BZ2_bzWrite(&bzError, pBz, const_cast<char*>(pwd.c_str()), (int)pwd.size());
          if (bzError != BZ_OK)
          {
            std::cerr << "ERROR while writing to BZ2 file." << std::endl;
            BZ2_bzWriteClose(&bzError, pBz, 0, nullptr, nullptr);
            fclose(bz2File);
            return EXIT_FAILURE;
          }
        }
        else
        {
          out << pwd;
        }
      }
    }
    std::cout << std::endl;
  }

  if (compress)
  {
    BZ2_bzWriteClose(&bzError, pBz, 0, nullptr, nullptr);
    if (bzError != BZ_OK)
    {
      std::cerr << "ERROR while closing BZ2 file." << std::endl;
      BZ2_bzWriteClose(&bzError, pBz, 0, nullptr, nullptr);
      fclose(bz2File);
      return EXIT_FAILURE;
    }
    fclose(bz2File);
  }

  std::cout << std::endl
            << "Ready." << std::endl;
  return EXIT_SUCCESS;
}
