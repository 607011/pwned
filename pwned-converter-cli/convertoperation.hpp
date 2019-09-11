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

#ifndef __convertoperation_hpp__
#define __convertoperation_hpp__

#include <string>
#include <vector>
#include <memory>

#include <operation.hpp>
#include <hash.hpp>
#include <passwordhashandcount.hpp>
#include <userpasswordreader.hpp>

class ConvertOperationPrivate;

class ConvertOperation : public pwned::Operation
{
public:
  std::shared_ptr<ConvertOperationPrivate> d;
  ConvertOperation(const std::string &srcFilename,
                   const std::string &dstDirectory,
                   const std::string &outputExt,
                   uint64_t maxMem,
                   const std::vector<pwned::UserPasswordReaderOptions> &options);
  void execute() noexcept(false) override;
};

#endif /* __convertoperation_hpp__ */
