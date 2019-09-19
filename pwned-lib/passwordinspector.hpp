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
#include "phchasher.hpp"

namespace pwned
{

class PasswordInspector
{
private:
  std::ifstream inputFile;
  std::ifstream indexFile;
  std::ifstream mphfFile;
  int64_t size;
  unsigned int shift;
  pwned::PasswordHashAndCount phc;
  MPHF mphf;

public:
  typedef uint64_t index_key_t;
  PasswordInspector();
  PasswordInspector(const std::string &inputFilename);
  PasswordInspector(const std::string &inputFilename, const std::string &indexFilename);
  ~PasswordInspector();
  bool open(const std::string &inputFilename);
  bool open(const std::string &inputFilename, const std::string &indexFilename);
  bool openWithMPHF(const std::string &inputFilename, const std::string &mphfFilename);
  PasswordHashAndCount lookup(const std::string &pwd);
  PasswordHashAndCount mphfSearch(const pwned::Hash &hash, int *readCount = nullptr);
  PasswordHashAndCount binSearch(const pwned::Hash &hash, int *readCount = nullptr);
  PasswordHashAndCount smartBinSearch(const pwned::Hash &hash, int *readCount = nullptr);
};

typedef PasswordInspector::index_key_t index_key_t;

} // namespace pwned

#endif // __passwordinspector_hpp__
