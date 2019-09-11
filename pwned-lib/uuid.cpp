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


#include <iomanip>

#include "uuid.hpp"

namespace pwned {

    std::ostream &operator<<(std::ostream &os, UUID const &uuid) {
        std::ostringstream ss;
        uint32_t a = (uuid.uuid[0] >> 32) & 0xffffffff;
        uint16_t b = (uuid.uuid[0] >> 16) & 0xffff;
        uint16_t c = uuid.uuid[0] & 0xffff;
        uint16_t d = (uuid.uuid[0] >> 48) & 0xffff;
        uint16_t e = (uuid.uuid[0] >> 32) & 0xffff;
        uint32_t f = uuid.uuid[0] & 0xffffffff;
        ss << std::hex << std::uppercase << std::setfill('0')
        << std::setw(8) << a << '-'
        << std::setw(4) << b << '-'
        << std::setw(4) << c << '-'
        << std::setw(4) << d << '-'
        << std::setw(4) << e
        << std::setw(8) << f;
        return os << ss.str();
    }

    static std::random_device rd;
    std::mt19937_64 UUID::random_uint64(rd());
    UUID::_init UUID::_initializer;

}
