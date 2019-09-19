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

#ifndef __phcfileiterator_hpp__
#define __phcfileiterator_hpp__

#include <istream>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <boost/filesystem.hpp>

#include <pwned-lib/passwordhashandcount.hpp>
#include <pwned-merger-cli/lazy.hpp>

namespace fs = boost::filesystem;

class PHCFileIterator
{
public:
  using iterator_category = std::forward_iterator_tag;
  using value_type = pwned::PasswordHashAndCount;
  using difference_type = std::ptrdiff_t;
  using pointer = const pwned::PasswordHashAndCount *;
  using reference = const pwned::PasswordHashAndCount &;

  PHCFileIterator()
      : f(nullptr)
      , pos(0)
      , lastPos(0)
      , isEnd(false)
  {
  }

  PHCFileIterator(std::ifstream *f)
      : f(f)
      , pos(0)
      , lastPos(0)
      , isEnd(false)
  {
    if (f != nullptr) {
      f->clear();
      advance();
    }
  }

  PHCFileIterator(std::ifstream *f, uint64_t lastPos)
      : f(f)
      , pos(0)
      , lastPos(lastPos)
      , isEnd(true)
  {
  }

  PHCFileIterator(const PHCFileIterator &other)
      : phc(other.phc)
      , f(other.f)
      , pos(other.pos)
      , lastPos(other.lastPos)
      , isEnd(other.isEnd)
	{
	}

  ~PHCFileIterator() = default;

  inline const pwned::PasswordHashAndCount &operator*()
  {
    return phc;
  }

  inline PHCFileIterator &operator++()
  {
    advance();
    return *this;
  }

  friend bool operator==(PHCFileIterator const &lhs, PHCFileIterator const &rhs)
  {
    if (lhs.f == rhs.f)
    {
      if (lhs.isEnd == rhs.isEnd)
      {
        return true;
      }
      if (lhs.isEnd)
      {
        return lhs.lastPos == rhs.pos;
      }
      else if (rhs.isEnd)
      {
        return lhs.pos == rhs.lastPos;
      }
      else
      {
        return lhs.pos == rhs.pos;
      }
    }
    return false;
  }

  friend bool operator!=(PHCFileIterator const &lhs, PHCFileIterator const &rhs)
  {
    return !(lhs == rhs);
  }

private:
  inline void advance()
  {
    ++pos;
    phc.read(*f);
  }

  pwned::PasswordHashAndCount phc;
  std::ifstream *f;
  uint64_t pos;
  uint64_t lastPos;
  bool isEnd;
};

class PHCFile
{
public:
  PHCFile()
      : f(nullptr)
  {
  }

  PHCFile(const std::string &filename)
      : fileSize([filename] {
          return uint64_t(fs::file_size(filename)) / pwned::PasswordHashAndCount::size;
        })
  {
    f = new std::ifstream(filename, std::ios::binary);
  }

  ~PHCFile()
  {
    if (f != nullptr)
    {
      delete f;
    }
  };

  bool is_open() const
  {
    return (f != nullptr) && f->is_open();
  }

  inline PHCFileIterator begin() const
  {
    return PHCFileIterator(f);
  }

  inline PHCFileIterator end() const
  {
    return PHCFileIterator(f, size());
  }

  inline size_t size() const
  {
    return fileSize.value();
  }

private:
  std::ifstream *f;
  Lazy<uint64_t> fileSize;
};

#endif // __phcfileiterator_hpp__
