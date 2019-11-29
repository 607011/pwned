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

#ifndef __operationexception_hpp__
#define __operationexception_hpp__

#include <exception>
#include <string>

namespace pwned {

class OperationException : public std::exception
{
protected:
  std::string mMsg;
  int mCode;

public:
  enum
  {
    OK = 0,
    QueueNotSet
  };

  OperationException(const char *message, int code);
  OperationException(const std::string &message, int code);
  const std::string &what() noexcept;
  const char *what() const noexcept;
  int code() const noexcept;
};

} // namespace pwned

#endif // __operationexception_hpp__
