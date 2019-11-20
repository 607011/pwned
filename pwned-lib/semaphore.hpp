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

#ifndef __semaphore_hpp__
#define __semaphore_hpp__

#include <mutex>
#include <condition_variable>
#include <sstream>
#include <iostream>

namespace pwned
{

class Semaphore
{
  std::mutex mtx;
  std::condition_variable cv;
  unsigned int _capacity;

public:
  Semaphore(unsigned int capacity = 0U)
      : _capacity(capacity)
  { /* ... */
  }

  Semaphore(const Semaphore &o)
      : Semaphore(o._capacity)
  { /* ... */
  }

  inline void setCapacity(unsigned int capacity)
  {
    if (capacity > 0)
    {
      _capacity = capacity - _capacity;
    }
  }

  inline unsigned int capacity() const
  {
    return _capacity;
  }

  inline void notify()
  {
    std::unique_lock<std::mutex> lock(mtx);
    ++_capacity;
    cv.notify_one();
  }

  inline void wait()
  {
    std::unique_lock<std::mutex> lock(mtx);
    while (_capacity == 0U)
    {
      cv.wait(lock);
    }
    --_capacity;
  }
};

} // namespace pwned

#endif // __semaphore_hpp__
