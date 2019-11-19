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
#include <iterator>
#include <thread>
#include <algorithm>
#include <chrono>

#include <boost/system/error_code.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/program_options.hpp>

#include <pwned-lib/operation.hpp>
#include <pwned-lib/operationqueue.hpp>
#include <pwned-lib/util.hpp>
#include <pwned-lib/uuid.hpp>

#include "progresscallback.hpp"
#include "mergeoperation.hpp"
#include "progressbar.hpp"

namespace fs = boost::filesystem;
namespace ba = boost::algorithm;
namespace po = boost::program_options;
using namespace std::chrono;

static const std::string DefaultOutputExt = ".md5";

po::options_description desc("Allowed options");

void hello()
{
  std::cout << "#pwned merger 0.9.1 - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void info()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-merger --warranty'." << std::endl
            << "This is free software, and you are welcome to redistribute it" << std::endl
            << "under certain conditions; see https://www.gnu.org/licenses/gpl-3.0.en.html" << std::endl
            << "for details." << std::endl
            << std::endl;
}

void warranty()
{
  std::cout << "Warranty info:" << std::endl << std::endl
            << "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION."
            << std::endl
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
  std::vector<std::string> filenames;
  std::string srcDirectory;
  std::string dstFile;
  std::string tmpDirectory = (fs::temp_directory_path() / "net.ersatzworld.pwned.merger").string();
  std::string outputExt = DefaultOutputExt;
  std::string inputExt = DefaultOutputExt;
  int maxFilesAtOnce = 50;
  desc.add_options()("help,?", "produce help message")
  ("src,S", po::value<std::string>(&srcDirectory), "set user:pass input directory")
  ("input,I", po::value<std::vector<std::string>>(), "set MD5:count input file(s)")
  ("output,O", po::value<std::string>(&dstFile), "set MD5:count output file")
  ("tmp,T", po::value<std::string>(&tmpDirectory)->default_value(tmpDirectory), "set working directory")
  ("max-files-at-once,n", po::value<int>(&maxFilesAtOnce)->default_value(maxFilesAtOnce), "process max files at once")
  ("ext,X", po::value<std::string>(&outputExt)->default_value(DefaultOutputExt), "set extension for output files")
  ("warranty,W", "show warranty info");
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
    return EXIT_FAILURE;
  }
  po::notify(vm);

  hello();
  if (vm.count("warranty") > 0)
  {
    warranty();
    return EXIT_SUCCESS;
  }
  if (vm.count("help") > 0)
  {
    usage();
    return EXIT_SUCCESS;
  }
  if (vm.count("src") == 0 && vm.count("input") == 0)
  {
    usage();
    return EXIT_FAILURE;
  }
  if (!srcDirectory.empty())
  {
    std::cout << "Scanning " << srcDirectory << " for files ... " << std::flush;
    fs::recursive_directory_iterator fileTreeIterator(srcDirectory);
    for (auto &&f : fileTreeIterator)
    {
      const std::string &filePath = f.path().string();
      if (ba::ends_with(filePath, inputExt) && fs::is_regular_file(f) && fs::file_size(filePath) > 0)
      {
        filenames.push_back(filePath);
      }
    }
    std::cout << "found " << filenames.size() << " files." << std::endl;
  }
  if (vm.count("input") > 0)
  {
    const std::vector<std::string> &moreFilenames = vm["input"].as<std::vector<std::string>>();
    filenames.insert(filenames.end(), std::make_move_iterator(moreFilenames.begin()), std::make_move_iterator(moreFilenames.end()));
  }
  if (dstFile.empty())
  {
    usage();
    return EXIT_FAILURE;
  }
  if (!fs::exists(tmpDirectory))
  {
    boost::system::error_code ec;
    fs::create_directories(tmpDirectory, ec);
    if (ec.value() != 0)
    {
      std::cerr << "Cannot create working directory " << tmpDirectory << "." << std::endl;
      return EXIT_FAILURE;
    }
  }
  std::cout << "Destination file: " << dstFile << std::endl
            << std::endl;
  high_resolution_clock::time_point t0 = high_resolution_clock::now();
  std::vector<InputFile> inputFiles;
  for (const auto &filename : filenames)
  {
    inputFiles.push_back(InputFile(filename));
  }
  std::sort(inputFiles.begin(), inputFiles.end(), InputFileLess);
  std::vector<std::string> intermediateFilenames;
  ProgressBar progressBar(32);
  pwned::OperationQueue<MergeOperation> opQueue;
  pwned::TermIO termIO;
  std::thread keyThread = pwned::runAsync([&opQueue, &termIO] {
    char ch;
    do
    {
      ch = char(getchar());
      switch (ch)
      {
      case 'p':
        if (opQueue.isRunning())
        {
          opQueue.pause();
        }
        else
        {
          opQueue.resume();
        }
        break;
      case 'q':
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
  while (inputFiles.size() > 0 && !opQueue.isCancelled())
  {
    const auto b = std::min(inputFiles.end(), inputFiles.begin() + maxFilesAtOnce);
    const std::vector<InputFile> inputFileSlice(inputFiles.begin(), b);
    const bool isLastChunk = inputFileSlice.size() == inputFiles.size();
    const std::string &targetFilename = isLastChunk
                                            ? dstFile
                                            : (fs::path(tmpDirectory) / fs::unique_path()).string() + outputExt;
    if (!isLastChunk)
    {
      intermediateFilenames.push_back(targetFilename);
    }
    const uint64_t chunkInputSize = std::accumulate(inputFileSlice.begin(),
                                                    inputFileSlice.end(),
                                                    0ULL,
                                                    [](uint64_t sum, const InputFile &file) {
                                                      return sum + file.inputSize.value();
                                                    });
    progressBar.setHi(chunkInputSize / pwned::PasswordHashAndCount::size);
    MergeOperation *const op = new MergeOperation(inputFileSlice, targetFilename, false, &progressBar);
    opQueue.add(op);
    opQueue.execute(true);
    opQueue.waitForFinished();
    if (!opQueue.isCancelled())
    {
      inputFiles = std::vector<InputFile>(b, inputFiles.end());
      if (!isLastChunk)
      {
        inputFiles.push_back(InputFile(targetFilename));
      }
      std::cout << inputFiles.size() << " files left." << std::endl;
    }
  }
  high_resolution_clock::time_point t1 = high_resolution_clock::now();
  duration<float> time_span = duration_cast<duration<float>>(t1 - t0);
  if (!opQueue.isCancelled())
  {
    std::cout << "Total time: " << pwned::readableTime(time_span.count()) << std::endl;
  }
  for (auto intermediateFile : intermediateFilenames)
  {
    fs::remove(intermediateFile);
  }
  return EXIT_SUCCESS;
}
