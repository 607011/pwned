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
#include <regex>

class URI
{
public:
  URI();
  explicit URI(const std::string &uri);
  bool isValid() const { return isValid_; }
  const std::string &host() const { return host_; } 
  const std::string &scheme() const { return scheme_; }
  const std::string &path() const { return path_; }
  const std::string &fragment() const { return fragment_; }
  const std::string &username() const { return username_; }
  const std::string &password() const { return password_; }
  unsigned short port() const { return port_; } 
  const std::map<std::string, std::string> &query() { return query_; }

  void parse(const std::string &uri);
  void parseTarget(const std::string &target);

private:
  static const std::regex RE;
  static const std::map<std::string, unsigned short> schemeToPort;

  bool isValid_;
  std::string scheme_;
  std::string host_;
  std::string username_;
  std::string password_;
  std::string path_;
  std::string fragment_;
  unsigned short port_;
  std::map<std::string, std::string> query_;
};

#endif // __URI_HPP__