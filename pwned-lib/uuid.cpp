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

#include <sstream>
#include <iomanip>
#include <chrono>

#include "uuid.hpp"

namespace pwned
{

std::ostream &operator<<(std::ostream &os, UUID const &uuid)
{
  const uint32_t a = (uuid.uuid[0] >> 32) & 0xffffffff;
  const uint16_t b = (uuid.uuid[0] >> 16) & 0xffff;
  const uint16_t c = uuid.uuid[0] & 0xffff;
  const uint16_t d = (uuid.uuid[0] >> 48) & 0xffff;
  const uint16_t e = (uuid.uuid[0] >> 32) & 0xffff;
  const uint32_t f = uuid.uuid[0] & 0xffffffff;
  std::ostringstream ss;
  ss << std::hex << std::uppercase << std::setfill('0')
     << std::setw(8) << a << '-'
     << std::setw(4) << b << '-'
     << std::setw(4) << c << '-'
     << std::setw(4) << d << '-'
     << std::setw(4) << e
     << std::setw(8) << f;
  return os << ss.str();
}

std::mt19937_64 UUID::rng{static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count())};

} // namespace pwned
