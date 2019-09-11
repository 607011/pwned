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

#ifndef __userpasswordreader_hpp__
#define __userpasswordreader_hpp__

#include <string>
#include <vector>
#include <memory>

#include "hash.hpp"

namespace pwned {

    enum UserPasswordReaderOptions {
        forceEvaluateMD5Hashes,
        forceEvaluateHexEncodedPasswords,
        autoEvaluateMD5Hashes,
        autoEvaluateHexEncodedPasswords
    };

    class UserPasswordReaderPrivate;

    class UserPasswordReader {
        std::unique_ptr<UserPasswordReaderPrivate> d;

    public:
        bool eof() const;
        bool bad() const;

        UserPasswordReader(const std::string &inputFilePath, const std::vector<UserPasswordReaderOptions> &options);
        ~UserPasswordReader();
        void evaluateContents();
        Hash nextPasswordHash();
    };

}

#endif /* __userpasswordreader_hpp__ */
