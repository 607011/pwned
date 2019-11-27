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
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdint>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/program_options.hpp>

#include <pwned-lib/operationqueue.hpp>
#include <pwned-lib/util.hpp>
#include <pwned-lib/uuid.hpp>

#include "userpasswordreader.hpp"
#include "convertoperation.hpp"

namespace fs = boost::filesystem;
namespace ba = boost::algorithm;
namespace po = boost::program_options;

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned converter 1.0.0 - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void info()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details" << std::endl
            << "type `pwned-merger --warranty'. This is free software, and" << std::endl
            << "you are welcome to redistribute it under certain conditions;" << std::endl
            << "type `pwned-merger --license' for details." << std::endl
            << std::endl;
}

void usage()
{
  std::cout << desc << std::endl;
}

static const std::string DefaultOutputExt = ".md5";
static const unsigned int DefaultNumThreads = 4;

int main(int argc, const char *argv[])
{
  hello();
  pwned::MemoryStat memStat;
  pwned::getMemoryStat(memStat);
  uint64_t memFreeAssumedMBytes = 0;
  std::cout << "Physical memory (total/app/available): "
            << pwned::readableSize(memStat.phys.total) << "/"
            << pwned::readableSize(memStat.phys.app) << "/"
            << pwned::readableSize(memStat.phys.avail)
            << std::endl
            << std::endl;
  std::vector<std::string> filenames;
  std::string srcDirectory;
  std::string dstDirectory;
  std::string outputExt = DefaultOutputExt;
  std::vector<pwned::UserPasswordReaderOptions> options;
  bool forceMD5 = false;
  bool autoMD5 = false;
  bool forceHex = false;
  bool autoHex = false;
  unsigned int numThreads;
  desc.add_options()("help", "produce help message")
  ("input,I", po::value<std::vector<std::string>>(), "set user:pass input file(s)")
  ("src,S", po::value<std::string>(&srcDirectory), "set user:pass input directory")
  ("dst,D", po::value<std::string>(&dstDirectory), "set user:pass output directory")
  ("ext", po::value<std::string>(&outputExt)->default_value(DefaultOutputExt), "set extension for output files")
  ("ram", po::value<uint64_t>(&memFreeAssumedMBytes)->default_value(memStat.phys.avail / 1024 / 1024), "program can use as many as the given MB of RAM (overrides automatic free memory detection)")
  ("threads,T", po::value<unsigned int>(&numThreads)->default_value(DefaultNumThreads), "run in this many threads")
  ("force-md5", po::bool_switch(&forceMD5), "convert MD5 encoded passwords")
  ("auto-md5", po::bool_switch(&autoMD5), "convert MD5 encoded passwords if some are found")
  ("force-hex", po::bool_switch(&forceHex), "convert hex encoded passwords")
  ("auto-hex", po::bool_switch(&autoHex), "convert hex encoded passwords if some are found");
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
  if (vm.count("help") > 0)
  {
    usage();
    return EXIT_SUCCESS;
  }
  if (numThreads == 0)
  {
    numThreads = DefaultNumThreads;
  }
  if (srcDirectory.size() > 0)
  {
    std::cout << "Scanning " << srcDirectory << " for files ..." << std::flush;
    fs::recursive_directory_iterator fileTreeIterator(srcDirectory);
    for (const auto &f : fileTreeIterator)
    {
      const std::string &filePath = f.path().string();
      if (fs::is_regular_file(f) && ba::ends_with(filePath, ".txt"))
      {
        filenames.push_back(filePath);
      }
    }
    std::cout << std::endl;
  }
  if (filenames.empty())
  {
    usage();
    return EXIT_FAILURE;
  }
  if (dstDirectory.empty())
  {
    usage();
    return EXIT_FAILURE;
  }
  if (forceMD5)
  {
    options.push_back(pwned::UserPasswordReaderOptions::forceEvaluateMD5Hashes);
  }
  else if (autoMD5)
  {
    options.push_back(pwned::UserPasswordReaderOptions::autoEvaluateMD5Hashes);
  }
  if (forceHex)
  {
    options.push_back(pwned::UserPasswordReaderOptions::forceEvaluateHexEncodedPasswords);
  }
  else if (autoHex)
  {
    options.push_back(pwned::UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords);
  }
  info();
  std::cout << "Converting " << filenames.size() << " files." << std::endl;
  std::cout << "Destination directory: " << dstDirectory << std::endl
            << std::endl;
  auto t0 = std::chrono::high_resolution_clock::now();
  std::cout << "Preparing queue ..." << std::endl;
  pwned::OperationQueue<ConvertOperation> opQueue;
  for (const auto &filename : filenames)
  {
    ConvertOperation *op = new ConvertOperation(filename,
                                                dstDirectory,
                                                outputExt,
                                                memFreeAssumedMBytes * 1024 * 1024 / uint64_t(numThreads),
                                                options);
    opQueue.add(op);
  }
  pwned::TermIO termIO;
  std::thread keyThread = pwned::runAsync([&opQueue, &termIO] {
    termIO.disableEcho();
    char ch;
    do
    {
      ch = char(getchar());
      switch (ch)
      {
      case ' ':
        if (opQueue.isRunning())
        {
          std::cout << "Pausing ... " << std::flush;
          opQueue.pause();
        }
        else
        {
          std::cout << "Resuming ... " << std::flush;
          opQueue.resume();
        }
        break;
      case 'q':
        std::cout << "Cancelling all operations ..." << std::endl;
        opQueue.resume();
        opQueue.cancel();
        break;
      default:
        break;
      }
    } while (ch != 'q');
  },
                                          0);
  keyThread.detach();
  std::cout << "Executing queue ..." << std::endl;
  std::cout << "([Space] to pause/resume, Q to quit)" << std::endl;
  opQueue.execute(true);
  opQueue.waitForFinished();
  auto t1 = std::chrono::high_resolution_clock::now();
  auto time_span = std::chrono::duration_cast<std::chrono::duration<float>>(t1 - t0);
  if (!opQueue.isCancelled())
  {
    std::cout << "Total time: " << pwned::readableTime(time_span.count()) << std::endl
              << std::endl;
  }
  return EXIT_SUCCESS;
}
