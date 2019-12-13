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
#include <vector>
#include <chrono>
#include <limits>
#include <functional>
#include <algorithm>
#include <numeric>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#if defined(__APPLE__)
extern "C"
{
  struct proc;
  struct vfs_purge_args;
  int vfs_purge(struct proc *, struct vfs_purge_args *, int *);
}
#elif defined(WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#endif

#include <pwned-lib/passwordhashandcount.hpp>
#include <pwned-lib/passwordinspector.hpp>
#include <pwned-lib/util.hpp>

namespace po = boost::program_options;
namespace fs = boost::filesystem;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned lookup benchmark 1.0.0 - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`benchmark --warranty`." << std::endl
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

int purgeFilesystemCacheOn(const std::string &filename)
{
  int rc = 0;
#if defined(__APPLE__)
  (void)(filename);
  if (geteuid() == 0)
  {
    std::cout << "Purging filesystem cache (this can take a couple of minutes) ... " << std::flush;
    vfs_purge(nullptr, nullptr, nullptr);
    std::cout << std::endl << std::endl;
  }
  else
  {
    std::cout << "** WARNING** This program needs root privileges to purge the filesystem cache." << std::endl
              << "** WARNING** Running benchmarks without purging first." << std::endl
              << std::endl;
    rc = 1;
  }
#elif defined(__linux__)
  (void)(filename);
  sync();
  std::ofstream ofs("/proc/sys/vm/drop_caches");
  ofs << '3' << std::endl;
#elif defined(WIN32)
  // https://stackoverflow.com/questions/478340/clear-file-cache-to-repeat-performance-testing/7113153#7113153
  HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    std::cerr << "ERROR: Cannot read '" << inputFilename << "'." << std::endl;
    rc = 1;
  }
  CloseHandle(hFile);
#else
  (void)(filename);
  sync(); // XXX
#endif
  return rc;
}

static const std::string AlgoBinSearch = "binsearch";
static const std::string AlgoSmartBinSearch = "smart";
static const std::vector<std::string> AlgoList = {AlgoBinSearch, AlgoSmartBinSearch};
static const std::string AlgoStringList = std::accumulate(std::next(AlgoList.begin()), AlgoList.end(), "'" + AlgoList.front() + "'", [](std::string a, const std::string &b) { return std::move(a) + ", '" + b + "'"; });

void benchmarkWithoutIndex(
  int nRuns,
  std::vector<double> &runTimes,
  const std::string &inputFilename,
  const std::vector<pwned::PasswordHashAndCount> &phcs,
#ifdef __linux__
  std::_Mem_fn<pwned::PasswordHashAndCount(pwned::PasswordInspector::*)(const pwned::Hash &, int *)> searchCallable
#else
  std::__mem_fn<pwned::PasswordHashAndCount(pwned::PasswordInspector::*)(const pwned::Hash &, int *)> searchCallable
#endif
  )
{
  for (int run = 1; run <= nRuns; ++run)
  {
    int nReads = 0;
    std::cout << "Benchmark run " << run << " of " << nRuns << " in progress ... " << std::flush;
    pwned::PasswordInspector inspector(inputFilename);
    std::function<pwned::PasswordHashAndCount(const pwned::Hash &, int *)> lookup = std::bind(searchCallable, &inspector, std::placeholders::_1, std::placeholders::_2);
    int found = 0;
    int notFound = 0;
    auto t0 = std::chrono::high_resolution_clock::now();
    for (const auto &phc : phcs)
    {
      int readCount = 0;
      try
      {
        const pwned::PHC &result = lookup(phc.hash, &readCount);
        nReads += readCount;
        if (result.count > 0)
        {
          ++found;
        }
        else
        {
          ++notFound;
        }
      }
      catch (const std::exception &e)
      {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return;
      }
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0);
    runTimes.push_back(time_span.count());
    std::cout << std::endl
              << "#reads: " << nReads << std::endl
              << "Found: " << found << std::endl
              << "Not found: " << notFound
              << std::endl
              << "Lookup time: " << pwned::readableTime(time_span.count())
              << " (" << std::setprecision(3) << (1e3 * time_span.count() / double(phcs.size())) << "ms per lookup)" << std::endl
              << std::endl;
  }
}

void benchmarkWithIndex(
  int nRuns,
  std::vector<double> &runTimes,
  const std::string &inputFilename,
  const std::vector<pwned::PasswordHashAndCount> &phcs,
  const std::string &indexFilename)
{
  for (int run = 1; run <= nRuns; ++run)
  {
    int nReads = 0;
    std::cout << "Benchmark run " << run << " of " << nRuns << " in progress ... " << std::flush;
    pwned::PasswordInspector inspector(inputFilename, indexFilename);
    int found = 0;
    int notFound = 0;
    auto t0 = std::chrono::high_resolution_clock::now();
    for (const auto &phc : phcs)
    {
      ++nReads;
      int readCount = 0;
      try
      {
        const pwned::PasswordHashAndCount &result = inspector.binsearch(phc.hash, &readCount);
        nReads += readCount;
        if (result.count > 0)
        {
          ++found;
        }
        else
        {
          ++notFound;
        }
      }
      catch (const std::exception &e)
      {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return;
      }
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    auto time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0);
    runTimes.push_back(time_span.count());
    std::cout << std::endl
              << "#reads: " << nReads << std::endl
              << "Found: " << found << std::endl
              << "Not found: " << notFound
              << std::endl
              << "Lookup time: " << pwned::readableTime(time_span.count())
              << " (" << std::setprecision(3) << (1e3 * time_span.count() / double(phcs.size())) << "ms per lookup)" << std::endl
              << std::endl;
  }
}

int main(int argc, const char *argv[])
{
  hello();
  std::string inputFilename;
  std::string testsetFilename;
  std::string indexFilename;
  std::string algorithm;
  static constexpr int DefaultNumberOfRuns = 5;
  bool doPurgeFilesystemCache = false;
  int nRuns = DefaultNumberOfRuns;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set user:pass input file")
  ("test-set,S", po::value<std::string>(&testsetFilename), "set user:pass test set file")
  ("runs,n", po::value<int>(&nRuns)->default_value(DefaultNumberOfRuns), "number of runs")
  ("algorithm,A", po::value<std::string>(&algorithm)->default_value(AlgoSmartBinSearch), std::string("lookup algorithm (" + AlgoStringList + ")").c_str())
  ("index,X", po::value<std::string>(&indexFilename), "set index file")
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
  auto searchCallable = std::mem_fn(&pwned::PasswordInspector::smart_binsearch);
  if (vm.count("algorithm"))
  {
    if (algorithm == AlgoBinSearch)
    {
      searchCallable = std::mem_fn(&pwned::PasswordInspector::binsearch);
    }
    else if (algorithm == AlgoSmartBinSearch)
    {
      searchCallable = std::mem_fn(&pwned::PasswordInspector::smart_binsearch);
    }
    else
    {
      std::cerr << "Invalid algorithm '" << algorithm << "'." << std::endl;
      return EXIT_FAILURE;
    }
  }
  if (inputFilename.size() == 0 || testsetFilename.size() == 0)
  {
    usage();
    return EXIT_FAILURE;
  }
  if (!fs::exists(inputFilename))
  {
    std::cerr << "ERROR: Input file '" << inputFilename << "' doesn't exist." << std::endl;
    return EXIT_FAILURE;
  }
  if (!fs::exists(testsetFilename))
  {
    std::cerr << "ERROR: Test set file '" << testsetFilename << "' doesn't exist." << std::endl;
    return EXIT_FAILURE;
  }
  if (nRuns < 1)
  {
    std::cout << "Invalid number of runs given. Defaulting to " << DefaultNumberOfRuns << std::endl;
    nRuns = DefaultNumberOfRuns;
  }

  if (doPurgeFilesystemCache)
  {
    purgeFilesystemCacheOn(inputFilename);
  }
  std::ifstream testset(testsetFilename, std::ios::binary);
  std::cout << "Reading test set ... " << std::flush;
  std::vector<pwned::PasswordHashAndCount> phcs;
  pwned::PasswordHashAndCount phc;
  while (phc.read(testset))
  {
    phcs.push_back(phc);
  }
  std::cout << phcs.size() << " hashes." << std::endl;
  std::vector<double> runTimes;
  if (indexFilename.empty())
  {
    std::cout << "Using *" << algorithm << "* algorithm." << std::endl;
    benchmarkWithoutIndex(nRuns, runTimes, inputFilename, phcs, searchCallable);
  }
  else {
    if (fs::file_size(indexFilename) % sizeof(uint64_t) == 0)
    {
      std::cout << "Using *binsearch* algorithm with index." << std::endl;
      benchmarkWithIndex(nRuns, runTimes, inputFilename, phcs, indexFilename);
    }
    else
    {
      std::cerr << "ERROR: Invalid index file." << std::endl;
    }
  }
  std::sort(runTimes.begin(), runTimes.end());
  std::cout << std::endl
            << "Overall lookup time (best/median/avg): " << pwned::readableTime(runTimes.front())
            << " / " << pwned::readableTime(runTimes.at(runTimes.size() / 2))
            << " / " << pwned::readableTime(std::accumulate(runTimes.begin(), runTimes.end(), 0.0) / double(runTimes.size()))
            << std::endl
            << std::endl;
  return EXIT_SUCCESS;
}
