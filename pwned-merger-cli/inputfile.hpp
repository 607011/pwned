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

#ifndef __inputfile_hpp__
#define __inputfile_hpp__

#include <boost/filesystem.hpp>
#include <lazy.hpp>

namespace fs = boost::filesystem;

struct InputFile
{
  enum State
  {
    pending,
    reading,
    finished,
    cancelled
  };

  fs::path path;
  uint64_t bytesProcessed;
  uint64_t totalSets;
  uint64_t setsWritten;
  State state;
  pwned::Lazy<uint64_t> inputSize;

  explicit InputFile(const fs::path &path)
      : path(path), state(State::pending), inputSize([path] { return uint64_t(fs::file_size(path)); })
  {
  }

  InputFile(const InputFile &o)
      : path(o.path), bytesProcessed(o.bytesProcessed), totalSets(o.totalSets), setsWritten(o.setsWritten), state(o.state), inputSize(o.inputSize)
  {
  }
};

struct
{
  bool operator()(const InputFile &a, const InputFile &b)
  {
    return a.inputSize.value() > b.inputSize.value();
  }
} InputFileLess;

#endif // __inputfile_hpp__
