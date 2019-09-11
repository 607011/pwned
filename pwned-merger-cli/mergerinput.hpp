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

#ifndef __mergerinput_hpp__
#define __mergerinput_hpp__

#include <iostream>
#include <fstream>

#include <boost/filesystem.hpp>

#include <passwordhashandcount.hpp>

#include "inputfile.hpp"

class MergerInput : public InputFile
{
public:
  pwned::PasswordHashAndCount phc;
  bool isValid;
  std::ifstream f;

  explicit MergerInput(const InputFile &inputFile)
      : InputFile(inputFile), isValid(false)
  { /* ... */
  }

  ~MergerInput()
  {
    if (f.is_open())
    {
      f.close();
    }
  }

  void open()
  {
    f.open(path.string(), std::ios::in | std::ios::binary);
    if (f.is_open())
    {
      read();
    }
  }

  inline bool read()
  {
    isValid = phc.read(f);
    return isValid;
  }

  void deleteFile()
  {
    boost::filesystem::remove(path);
  }
};

#endif // __mergerinput_hpp__
