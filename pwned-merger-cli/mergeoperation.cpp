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
#include <queue>
#include <string>
#include <algorithm>
#include <chrono>
#include <cstdint>

#include <boost/filesystem.hpp>

#include <util.hpp>
#include <hash.hpp>
#include <passwordhashandcount.hpp>

#include "mergeoperation.hpp"
#include "inputfile.hpp"
#include "mergerinput.hpp"

namespace fs = boost::filesystem;
using namespace std::chrono;

struct SmallestHashFirst
{
  bool operator()(const MergerInput *lhs, const MergerInput *rhs)
  {
    return lhs->phc.hash > rhs->phc.hash;
  }
};

enum MergerError
{
  noData,
  cannotWriteToFile,
  cancelled
};

class MergeOperationPrivate
{
public:
  std::priority_queue<MergerInput *, std::vector<MergerInput *>, SmallestHashFirst> pq;
  const fs::path dstFilePath;
  std::ofstream dstFile;
  uint64_t entriesProcessed;
  bool removeInputFilesAfterMerge;
  pwned::ProgressCallback *progressed;
  uint64_t totalEntries;

  MergeOperationPrivate(const std::vector<InputFile> &srcFiles,
                        const std::string &dstFilename,
                        bool removeInputFilesAfterMerge,
                        pwned::ProgressCallback *progressCallback)
      : dstFilePath(dstFilename), entriesProcessed(0), removeInputFilesAfterMerge(false), progressed(progressCallback)
  {
    uint64_t sum = 0;
    for (auto file : srcFiles)
    {
      MergerInput *mi = new MergerInput(file);
      mi->open();
      pq.push(mi);
      sum += uint64_t(mi->inputSize.value());
    }
    totalEntries = sum / pwned::PasswordHashAndCount::size;
  }

  ~MergeOperationPrivate()
  {
    while (!pq.empty())
    {
      MergerInput *mi = pq.top();
      pq.pop();
      delete mi;
    }
  }
};

MergeOperation::MergeOperation(const std::vector<InputFile> &srcFiles,
                               const std::string &dstFile,
                               bool removeInputFilesAfterMerge,
                               pwned::ProgressCallback *progressCallback)
    : d(std::shared_ptr<MergeOperationPrivate>(new MergeOperationPrivate(srcFiles,
                                                                         dstFile,
                                                                         removeInputFilesAfterMerge,
                                                                         progressCallback)))
{
}

void MergeOperation::execute() noexcept(false)
{
  if (isCancelled)
    return;
  high_resolution_clock::time_point t0 = high_resolution_clock::now();
  if (d->pq.empty())
  {
    return;
  }
  {
    std::ostringstream output;
    output << "Merging into " << d->dstFilePath.string()
           << " (" << d->pq.size() << " files, " << d->totalEntries << " entries) ..."
           << std::endl;
    std::cout << output.str();
  }
  d->dstFile.open(d->dstFilePath.string(), std::ios::out | std::ios::binary);
  if (!d->dstFile.is_open())
  {
    std::cerr << "Cannot open '" << d->dstFilePath.string() << "' for writing: " << std::strerror(errno) << std::endl;
    throw pwned::OperationException(std::string("Cannot write to file: ") + std::strerror(errno), MergerError::cannotWriteToFile);
    return;
  }
  pwned::PasswordHashAndCount current = d->pq.top()->phc;
  uint64_t updateAfterEntries = std::max(d->totalEntries / 1000, uint64_t(1));
  while (!isCancelled)
  {
    const pwned::PasswordHashAndCount &p = next();
    if (!d->pq.empty())
    {
      if (d->progressed != nullptr && d->entriesProcessed % updateAfterEntries == 0)
      {
        (*d->progressed)(d->entriesProcessed);
      }
      ++d->entriesProcessed;
      if (current.hash == p.hash)
      {
        current.count += p.count;
      }
      else
      {
        current.dump(d->dstFile);
        current = p;
      }
    }
    else
    {
      current.dump(d->dstFile);
      break;
    }
    if (isPaused)
    {
      queue->operationWait();
      isPaused = false;
    }
  }
  d->dstFile.close();
  if (d->progressed != nullptr)
  {
    (*d->progressed)(d->entriesProcessed);
  }
  high_resolution_clock::time_point t1 = high_resolution_clock::now();
  duration<float> time_span = duration_cast<duration<float>>(t1 - t0);
  std::cout << "(" << pwned::readableTime(time_span.count()) << ")" << std::endl;
}

pwned::PasswordHashAndCount MergeOperation::next()
{
  pwned::PasswordHashAndCount result;
  if (!d->pq.empty())
  {
    MergerInput *mergerInput = d->pq.top();
    result = mergerInput->phc;
    if (mergerInput->isValid)
    {
      mergerInput->read();
      if (mergerInput->isValid)
      {
        d->pq.pop();
        d->pq.push(mergerInput);
      }
    }
    else
    {
      d->pq.pop();
      if (d->removeInputFilesAfterMerge)
      {
        mergerInput->deleteFile();
      }
      delete mergerInput;
      if (d->pq.empty())
      {
        return pwned::PasswordHashAndCount();
      }
    }
  }
  return result;
}
