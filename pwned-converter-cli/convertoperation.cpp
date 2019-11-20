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
#include <map>

#include <boost/filesystem.hpp>

#include <pwned-lib/util.hpp>
#include <pwned-lib/operationqueue.hpp>

#include "userpasswordreader.hpp"
#include "convertoperation.hpp"

namespace fs = boost::filesystem;

class ConvertOperationPrivate
{
public:
  ConvertOperationPrivate(const std::string &srcFilename,
                          const std::string &dstDirectory,
                          const std::string &outputExt,
                          uint64_t maxMem,
                          const std::vector<pwned::UserPasswordReaderOptions> &options)
      : srcFilePath(srcFilename), dstPath(dstDirectory), outputExt(outputExt), maxMem(maxMem), options(options)
  {
  }
  const fs::path srcFilePath;
  const fs::path dstPath;
  const fs::path outputExt;
  const uint64_t maxMem;
  const std::vector<pwned::UserPasswordReaderOptions> options;
};

ConvertOperation::ConvertOperation(const std::string &srcFilename,
                                   const std::string &dstDirectory,
                                   const std::string &outputExt,
                                   uint64_t maxMem,
                                   const std::vector<pwned::UserPasswordReaderOptions> &options)
    : d(std::shared_ptr<ConvertOperationPrivate>(new ConvertOperationPrivate(srcFilename,
                                                                             dstDirectory,
                                                                             outputExt,
                                                                             maxMem,
                                                                             options)))
{
  priority = (long long)(fs::file_size(srcFilename));
}

void ConvertOperation::execute() noexcept(false)
{
  if (isCancelled)
    return;
  {
    std::ostringstream output;
    output << uuid << " "
           << "Converting " << d->srcFilePath.string()
           << " into directory " << d->dstPath.string()
           << " (" << pwned::readableSize((uint64_t)priority) << "/" << pwned::readableSize(d->maxMem) << ") ..."
           << std::endl;
    std::cout << output.str();
  }
  pwned::UserPasswordReader reader(d->srcFilePath.string(), d->options);
  static const uint64_t estimatedMemoryOverheadPerEntry = sizeof(uintptr_t);
  static const uint64_t memUsagePerEntry = sizeof(pwned::Hash) + sizeof(uint32_t) + sizeof(pwned::PasswordHashAndCount) + estimatedMemoryOverheadPerEntry;
  int splitFileNum = 0;
  while (!reader.eof())
  {
    uint64_t memUsage = 0;
    ++splitFileNum;
    std::map<pwned::Hash, uint32_t, pwned::HashLess> passwordCountSet;
    while (!reader.eof() && !reader.bad() && memUsage < d->maxMem)
    {
      const pwned::Hash &hash = reader.nextPasswordHash();
      if (hash.isValid)
      {
        passwordCountSet[hash] += 1;
      }
      memUsage += memUsagePerEntry;
      if (isPaused)
      {
        queue->operationWait();
        isPaused = false;
      }
    }
    if (isCancelled)
      return;
    if (isPaused)
    {
      queue->operationWait();
      isPaused = false;
    }
    if (passwordCountSet.empty())
    {
      {
        std::ostringstream output;
        output << uuid << " "
               << "Nothing to write." << std::endl;
        std::cout << output.str();
      }
      continue;
    }
    std::vector<pwned::PasswordHashAndCount> passwordList;
    passwordList.reserve(passwordCountSet.size());
    for (auto const &i : passwordCountSet)
    {
      passwordList.push_back(pwned::PasswordHashAndCount(i.first, i.second));
    }
    if (isCancelled)
      return;
    if (isPaused)
    {
      queue->operationWait();
      isPaused = false;
    }
    std::sort(passwordList.begin(), passwordList.end(), pwned::PasswordHashAndCountLess());
    if (isCancelled)
      return;
    if (isPaused)
    {
      queue->operationWait();
      isPaused = false;
    }

    const fs::path srcFilename = d->srcFilePath.stem();

    auto generatedOutputFilename = [this, &srcFilename, splitFileNum]() {
      return (d->dstPath / (srcFilename.string() + ' ' + pwned::string_format("[%04x]", splitFileNum))).string();
    };

    fs::path dstFilePath = generatedOutputFilename() + d->outputExt.string();
    int n = 1;
    while (fs::exists(dstFilePath) && n < 10000)
    {
      dstFilePath = generatedOutputFilename() + pwned::string_format(" (%04x)", splitFileNum) + d->outputExt.string();
      ++n;
    }
    {
      std::ostringstream output;
      output << uuid << " Writing to " << dstFilePath.string() << " ..." << std::endl;
      std::cout << output.str();
    }
    std::ofstream f(dstFilePath.string(), std::ios::out | std::ios::binary);
    if (f.is_open())
    {
      for (auto &phc : passwordList)
      {
        phc.dump(f);
      }
      f.close();
    }
    if (isPaused)
    {
      queue->operationWait();
      isPaused = false;
    }
  }
}
