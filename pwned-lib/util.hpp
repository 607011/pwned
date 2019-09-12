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

#ifndef __util_hpp__
#define __util_hpp__

#include <string>
#include <termios.h>
#include <cstdint>

namespace pwned
{

struct MemoryStat
{
  struct
  {
    uint64_t total;
    uint64_t avail;
    uint64_t used;
    uint64_t app;
  } virt;
  struct
  {
    uint64_t total;
    uint64_t avail;
    uint64_t used;
    uint64_t app;
  } phys;
};

extern int getMemoryStat(MemoryStat &memoryStat);
extern std::string string_format(const std::string fmt_str, ...);
extern std::string readableSize(long long size);
extern std::string readableTime(double t);

class TermIO
{
  // struct termios t;
  struct termios old_t;

public:
  TermIO();
  ~TermIO();
  void disableEcho();
  void enableEcho();
  void disableBreak();
  void enableBreak();
};
}; // namespace pwned

#endif // __util_hpp__
