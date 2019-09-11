/*
 Copyright © 2019 Oliver Lau <oliver@ersatzworld.net>

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

#include <sys/types.h>

#include "passwordhashandcount.hpp"

namespace pwned
{

class PasswordInspector
{
private:
  std::ifstream f;
  int64_t size;
  pwned::PasswordHashAndCount phc;

public:
  PasswordInspector();
  PasswordInspector(const std::string &filename);
  ~PasswordInspector();
  bool open(const std::string &filename);
  PasswordHashAndCount lookup(const std::string &pwd);
  PasswordHashAndCount binsearch(const pwned::Hash &hash, int *readCount = nullptr);
  PasswordHashAndCount smart_binsearch(const pwned::Hash &hash, int *readCount = nullptr);
};

} // namespace pwned

#endif // __passwordinspector_hpp__
