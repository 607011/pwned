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

#include <iostream>
#include <algorithm>
#include <limits>

#include <boost/filesystem.hpp>

#include "passwordinspector.hpp"

namespace fs = boost::filesystem;

namespace pwned {
    
    PasswordInspector::PasswordInspector()
    : size(0)
    { /* ... */ }

    PasswordInspector::PasswordInspector(const std::string &filename) {
        open(filename);
    }
    
    PasswordInspector::~PasswordInspector() = default;
    
    bool PasswordInspector::open(const std::string &filename) {
        size = int64_t(fs::file_size(filename));
        f.open(filename, std::ios::in | std::ios::binary);
        return f.is_open();
    }
    
    PasswordHashAndCount PasswordInspector::binsearch(const pwned::Hash &hash) {
        PasswordHashAndCount phc;
        if (size > 0 && (size % pwned::PasswordHashAndCount::size == 0)) {
            int64_t lo = 0;
            int64_t hi = size;
            while (lo <= hi) {
                int64_t pos = (lo + hi) / 2;
                pos -= pos % pwned::PasswordHashAndCount::size;
                pos = std::max<int64_t>(0, pos);
                phc.read(f, pos);
                if (hash > phc.hash) {
                    lo = pos + pwned::PasswordHashAndCount::size;
                }
                else if (hash < phc.hash) {
                    hi = pos - pwned::PasswordHashAndCount::size;
                }
                else {
                    return phc;
                }
            }
            phc.count = 0;
        }
        return phc;
    }

    PasswordHashAndCount PasswordInspector::smart_fuzzy_binsearch(const pwned::Hash &hash) {
        PasswordHashAndCount phc;
        if (size > 0 && (size % pwned::PasswordHashAndCount::size == 0)) {
            const int64_t potentialHit = int64_t(float(size) * float(hash.upper) / float(std::numeric_limits<uint64_t>::max()));
            const int64_t offset = int64_t(size >> 9);
            int64_t lo = std::max<int64_t>(0, potentialHit - offset);
            int64_t hi = std::min<int64_t>(size, potentialHit + offset);
            while (lo <= hi) {
                int64_t pos = (lo + hi) / 2;
                pos = std::max<int64_t>(0, pos - pos % pwned::PasswordHashAndCount::size);
                phc.read(f, pos);
                if (hash > phc.hash) {
                    lo = pos + pwned::PasswordHashAndCount::size;
                }
                else if (hash < phc.hash) {
                    hi = pos - pwned::PasswordHashAndCount::size;
                }
                else {
                    return phc;
                }
            }
            phc.count = 0;
        }
        return phc;
    }

    PasswordHashAndCount PasswordInspector::smart_binsearch(const pwned::Hash &hash) {
        PasswordHashAndCount phc;
        if (size > 0 && (size % pwned::PasswordHashAndCount::size == 0)) {
            static constexpr int64_t OffsetMultiplicator = 2;
            int64_t potentialHitIdx = int64_t(float(size) * float(hash.upper) / float(std::numeric_limits<uint64_t>::max()));
            potentialHitIdx -= potentialHitIdx % pwned::PasswordHashAndCount::size;
            int64_t offset = std::max<int64_t>(int64_t(size >> 12), pwned::PasswordHashAndCount::size);
            offset -= offset % pwned::PasswordHashAndCount::size;
            int64_t lo = std::max<int64_t>(0, potentialHitIdx - offset);
            int64_t hi = std::min<int64_t>(size - pwned::PasswordHashAndCount::size, potentialHitIdx + offset);
            bool ok = false;
            Hash h0;
            ok = h0.read(f, lo);
            if (!ok) {
                throw("[PasswordInspector] Cannot read @ lo = " + std::to_string(lo));
            }
            while (hash < h0 && lo >= offset) {
                lo -= offset;
                h0.read(f, lo);
                offset *= OffsetMultiplicator;
//                std::cout << '-';
            }
            Hash h1;
            ok = h1.read(f, hi);
            if (!ok) {
                throw("[PasswordInspector] Cannot read @ hi = " + std::to_string(hi));
            }
            while (hash > h1 && hi <= size - offset - pwned::PasswordHashAndCount::size) {
                hi += offset;
                h1.read(f, hi);
                offset *= OffsetMultiplicator;
//                std::cout << '+';
            }
//            std::cout << h0 << " < " << hash << " < " << h1 << std::endl;
            if (!(h0 <= hash && hash <= h1)) {
                throw("[PasswordInspector] Hash out of bounds: !(" + h0.toString() + " < " + hash.toString() + " < " + h1.toString() + ")");
            }
            while (lo <= hi) {
                int64_t pos = (lo + hi) / 2;
                pos = std::max<int64_t>(0, pos - pos % pwned::PasswordHashAndCount::size);
                phc.read(f, pos);
                if (hash > phc.hash) {
                    lo = pos + pwned::PasswordHashAndCount::size;
                }
                else if (hash < phc.hash) {
                    hi = pos - pwned::PasswordHashAndCount::size;
                }
                else {
                    return phc;
                }
            }
            phc.count = 0;
        }
        return phc;
    }
    
    PasswordHashAndCount PasswordInspector::lookup(const std::string &pwd) {
        return binsearch(pwned::Hash(pwd));
    }
}
