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

#ifndef __URI_HPP__
#define __URI_HPP__

#include <string>
#include <map>
#include <cstdint>

class URI
{
public:
  URI();
  URI(URI &&) = delete;
  URI(const std::string &uri);
  bool isValid() const;
  void parse(const std::string &uri);
  void parseTarget(const std::string &target);
  const std::string &host() const;
  const std::string &scheme() const;
  const std::string &path() const;
  const std::string &fragment() const;
  const std::string &username() const;
  const std::string &password() const;
  uint16_t port() const;
  const std::map<std::string, std::string> &query();

private:
  static const std::map<std::string, uint16_t> SchemeToPort;

  bool mIsValid;
  std::string mScheme;
  std::string mHost;
  std::string mUsername;
  std::string mPassword;
  std::string mPath;
  std::string mFragment;
  uint16_t mPort;
  std::map<std::string, std::string> mQuery;
};

#endif // __URI_HPP__