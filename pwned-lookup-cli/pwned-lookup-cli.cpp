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
#include <chrono>

#include <boost/program_options.hpp>

#include <pwned-lib/passwordinspector.hpp>
#include <pwned-lib/algorithms.hpp>
#include <pwned-lib/util.hpp>

namespace po = boost::program_options;

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void setStdinEcho(bool enable)
{
#ifdef WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode;
  GetConsoleMode(hStdin, &mode);
  if (!enable)
  {
    mode &= ~ENABLE_ECHO_INPUT;
  }
  else
  {
    mode |= ENABLE_ECHO_INPUT;
  }
  SetConsoleMode(hStdin, mode);
#else
  struct termios tty;
  tcgetattr(STDIN_FILENO, &tty);
  if (!enable)
  {
    tty.c_lflag &= ~ECHO;
  }
  else
  {
    tty.c_lflag |= ECHO;
  }
  (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned lookup 1.0-RC - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-lookup-cli --warranty'." << std::endl
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
  std::string indexFilename;
  std::string mphfFilename;
  std::string algorithm;
  bool doPurgeFilesystemCache = false;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set MD5:count input file")
  ("index,X", po::value<std::string>(&indexFilename), "set index file")
  ("hash,H", po::value<std::string>(&mphfFilename), "set MPHF hashtable file")
  ("algorithm,A", po::value<std::string>(&algorithm)->default_value(pwned::AlgoSmartBinSearch), std::string("lookup algorithm (" + pwned::AlgoStringList + ")").c_str())
  ("purge", po::bool_switch(&doPurgeFilesystemCache), "Purge filesystem cache before running benchmark (needs root privileges)")
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

  pwned::PasswordInspector inspector;
  auto searchCallable = std::mem_fn(&pwned::PasswordInspector::smartBinSearch);

  if (!mphfFilename.empty())
  {
    std::cout << "Loading MPHF hash table ..." << std::endl;
    inspector.openWithMPHF(inputFilename, mphfFilename);
    algorithm = pwned::AlgoMPHFSearch;
    searchCallable = std::mem_fn(&pwned::PasswordInspector::mphfSearch);
  }
  else if (!indexFilename.empty())
  {
    std::cout << "Using index ..." << std::endl;
    algorithm = pwned::AlgoBinSearch;
    searchCallable = std::mem_fn(&pwned::PasswordInspector::binSearch);
    inspector.openWithIndex(inputFilename, indexFilename);
  }
  else
  {
    inspector.open(inputFilename);
  }

  if (vm.count("algorithm") > 0 && mphfFilename.empty() && indexFilename.empty())
  {
    if (algorithm == pwned::AlgoBinSearch)
    {
      searchCallable = std::mem_fn(&pwned::PasswordInspector::binSearch);
    }
    else if (algorithm == pwned::AlgoSmartBinSearch)
    {
      searchCallable = std::mem_fn(&pwned::PasswordInspector::smartBinSearch);
    }
    else
    {
      std::cerr << "Invalid algorithm '" << algorithm << "'." << std::endl;
      return EXIT_FAILURE;
    }
  }
  std::cout << "Using *" << algorithm << "* algorithm ..." << std::endl;
  auto lookup = std::bind(searchCallable, &inspector, std::placeholders::_1, std::placeholders::_2);


  for (;;)
  {
    if (doPurgeFilesystemCache)
    {
      pwned::purgeFilesystemCacheOn(inputFilename);
    }
    std::cout << "Password? ";
    std::string pwd;
    setStdinEcho(false);
    std::cin >> pwd;
    setStdinEcho(true);
    const pwned::Hash soughtHash(pwd);
    std::cout << std::endl
              << "MD5 hash " << soughtHash << std::endl;
    int nReads = 0;
    const auto &t0 = std::chrono::high_resolution_clock::now();
    pwned::PasswordHashAndCount phc = lookup(soughtHash, &nReads);
    const auto &t1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0);
    if (phc.count > 0)
    {
      if (!mphfFilename.empty())
      {
        std::cout << "Found." << std::endl;
      }
      else if (phc.count == 1)
      {
        std::cout << "Found once." << std::endl;
      }
      else
      {
        std::cout << "Found " << phc.count << " times." << std::endl;
      }
    }
    else
    {
      std::cout << "Not found." << std::endl;
    }
    std::cout << "Lookup time: " << time_span.count() * 1000 << " ms" << std::endl
              << "Number of read() operations: " << nReads << std::endl
              << std::endl;
  }
  return EXIT_SUCCESS;
}
