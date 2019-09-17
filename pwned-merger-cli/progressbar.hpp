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

#ifndef __progressbar_hpp__
#define __progressbar_hpp__

#include <iostream>
#include <iomanip>
#include <cstdint>

#include <pwned-lib/util.hpp>

#include "progresscallback.hpp"

class ProgressBar : public ProgressCallback
{
  uint64_t hi;
  int width;

public:
  enum Default
  {
    Begin = '[',
    Fill = '=',
    Space = ' ',
    End = ']'
  };
  char begin;
  char fill;
  char space;
  char end;

  ProgressBar(int width, uint64_t hi = 0)
      : hi(hi)
      , width(width)
      , begin(Default::Begin)
      , fill(Default::Fill)
      , space(Default::Space)
      , end(Default::End)
  { /* ... */
  }

  void setHi(uint64_t hi)
  {
    this->hi = hi;
  }

  void update(uint64_t value) override
  {
    std::cout << '\r' << begin;
    const int w = int(uint64_t(width) * value / hi);
    for (int i = 0; i < w; ++i)
    {
      std::cout << fill;
    }
    for (int i = w; i < width; ++i)
    {
      std::cout << space;
    }
    const float percent = 100 * float(value) / float(hi);
    std::cout << end << std::setw(5) << std::setfill(' ') << pwned::string_format(" %5.1f %% ", percent) << std::flush;
  }
};

#endif // __progressbar_hpp__
