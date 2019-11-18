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

#ifndef __uuid_hpp__
#define __uuid_hpp__

#include <ostream>
#include <random>
#include <cstdint>


namespace pwned
{

struct UUID
{
  static std::mt19937_64 rng;
  uint64_t uuid[2];
  UUID()
  {
    uuid[0] = rng();
    uuid[1] = rng();
  }
  bool operator==(const UUID &o) const
  {
    return uuid[0] == o.uuid[0] && uuid[1] == o.uuid[1];
  }
};

std::ostream &operator<<(std::ostream &os, UUID const &uuid);

} // namespace pwned

#endif // __uuid_hpp__
