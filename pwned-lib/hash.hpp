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

#ifndef __hash_hpp__
#define __hash_hpp__

#include <ostream>
#include <fstream>
#include <string>
#include <sys/types.h>
#include <openssl/md5.h>

namespace pwned {
    static constexpr int HashSize = MD5_DIGEST_LENGTH;

    struct Hash {
        union {
            uint8_t data[HashSize];
            struct {
                uint64_t upper;
                uint64_t lower;
            };
        };
        bool isValid;
        Hash();
        Hash(const Hash &);
        explicit Hash(const std::string &pwd);
        Hash(uint64_t upper, uint64_t lower);
        void toLittleEndian();
        
        inline bool read(std::ifstream &f) {
            f.read((char*)data, HashSize);
            return f.gcount() == HashSize;
        }
        
        inline bool read(std::ifstream &f, uint64_t pos) {
            f.seekg(pos);
            return read(f);
        }

        static Hash fromHex(const std::string &seq);
        std::string toString() const;

        inline Hash &operator=(const Hash &rhs) {
            upper = rhs.upper;
            lower = rhs.lower;
            return *this;
        }
    };

    inline bool operator==(const Hash &lhs, const Hash &rhs) {
        return lhs.upper == rhs.upper && lhs.lower == rhs.lower;
    }

    inline bool operator!=(const Hash &lhs, const Hash &rhs) {
        return lhs.upper != rhs.upper || lhs.lower != rhs.lower;
    }

    inline bool operator<(const Hash &lhs, const Hash &rhs) {
        if (lhs.upper == rhs.upper) {
            return lhs.lower < rhs.lower;
        }
        return lhs.upper < rhs.upper;
    }

    inline bool operator<=(const Hash &lhs, const Hash &rhs) {
        return lhs == rhs || lhs < rhs;
    }

    inline bool operator>(const Hash &lhs, const Hash &rhs) {
        if (lhs.upper == rhs.upper) {
            return lhs.lower > rhs.lower;
        }
        return lhs.upper > rhs.upper;
    }
    
    inline bool operator>=(const Hash &lhs, const Hash &rhs) {
        return lhs == rhs || lhs > rhs;
    }
    
    std::ostream &operator<<(std::ostream &os, Hash const &h);

    struct HashLess {
        bool operator() (const Hash &lhs, const Hash &rhs) const {
            return lhs < rhs;
        }
    };

}


#endif /* __hash_hpp__ */
