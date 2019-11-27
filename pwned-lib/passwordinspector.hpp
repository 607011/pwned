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

#ifndef __passwordinspector_hpp__
#define __passwordinspector_hpp__

#include <fstream>
#include <string>
#include <cstdint>

#include "passwordhashandcount.hpp"

namespace pwned
{

class PasswordInspector
{
private:
  std::ifstream mInputFile;
  std::ifstream mIndexFile;
  int64_t mFileSize{0};
  unsigned int mShift{0};
  pwned::PasswordHashAndCount mPHC;

public:
  typedef uint64_t index_key_t;
  PasswordInspector(const std::string &inputFilename);
  PasswordInspector(const std::string &inputFilename, const std::string &indexFilename);
  bool open(const std::string &inputFilename);
  bool open(const std::string &inputFilename, const std::string &indexFilename);
  bool isOpen() const;
  std::size_t size() const;
  PasswordHashAndCount lookup(const std::string &pwd);
  PasswordHashAndCount binsearch(const pwned::Hash &hash, int *readCount = nullptr);
  PasswordHashAndCount smart_binsearch(const pwned::Hash &hash, int *readCount = nullptr);
};

typedef PasswordInspector::index_key_t index_key_t;

} // namespace pwned

#endif // __passwordinspector_hpp__
