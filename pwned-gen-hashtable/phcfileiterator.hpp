#ifndef __phcfileiterator_hpp__
#define __phcfileiterator_hpp__

#include <istream>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <boost/filesystem.hpp>

#include <pwned-lib/passwordhashandcount.hpp>

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
  {
  }

  explicit PHCFileIterator(std::ifstream *f)
    : f(f)
    , pos(0)
  {
    if (f != nullptr) {
      f->clear();
      advance();
    }
  }

  PHCFileIterator(const PHCFileIterator &other)
    : phc(other.phc)
    , f(other.f)
    , pos(other.pos)
	{
	}

  ~PHCFileIterator() = default;

  pwned::PasswordHashAndCount const &operator*()
  {
    return phc;
  }

  PHCFileIterator &operator++()
  {
    advance();
    return *this;
  }

  friend bool operator==(PHCFileIterator const &lhs, PHCFileIterator const &rhs)
  {
    if (!lhs.f || !rhs.f)
    {
      if (!lhs.f && !rhs.f)
      {
        return true;
      }
      else
      {
        return false;
      }
    }
    return rhs.pos == lhs.pos;
  }

  friend bool operator!=(PHCFileIterator const &lhs, PHCFileIterator const &rhs)
  {
    return !(lhs == rhs);
  }

private:
  void advance()
  {
    ++pos;
    phc.read(*f);
  }

  pwned::PasswordHashAndCount phc;
  std::ifstream *f;
  uint64_t pos;
};

class PHCFile
{
public:
  PHCFile()
    : f(nullptr)
  {
  }

  PHCFile(const std::string &filename)
  {
    f = new std::ifstream();
    f->open(filename, std::ios::binary);
    if (!f->is_open())
    {
      throw std::invalid_argument(std::string("Error opening ") + filename);
    }
  }

  ~PHCFile()
  {
    if (f != nullptr)
    {
      delete f;
    }
  };

  PHCFileIterator begin() const
  {
    return PHCFileIterator(f);
  }

  PHCFileIterator end() const
  {
    return PHCFileIterator();
  }

  size_t size() const
  {
    return 0;
  }

private:
  std::ifstream *f;
};

#endif // __phcfileiterator_hpp__
