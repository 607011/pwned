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

#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>

#include "uri.hpp"

const std::regex URI::RE("^([a-z0-9+.-]+):(?:\\/\\/(?:((?:[a-z0-9-._~!$&'()*+,;=:]|%[0-9A-F]{2})*)@)?((?:[a-z0-9-._~!$&'()*+,;=]|%[0-9A-F]{2})*)(?::(\\d*))?(\\/(?:[a-z0-9-._~!$&'()*+,;=:@\\/]|%[0-9A-F]{2})*)?|(\\/?(?:[a-z0-9-._~!$&'()*+,;=:@]|%[0-9A-F]{2})+(?:[a-z0-9-._~!$&'()*+,;=:@\\/]|%[0-9A-F]{2})*)?)(?:\\?((?:[a-z0-9-._~!$&'()*+,;=:\\/?@]|%[0-9A-F]{2})*))?(?:#((?:[a-z0-9-._~!$&'()*+,;=:\\/?@]|%[0-9A-F]{2})*))?$");
const std::map<std::string, unsigned short> URI::schemeToPort = {
  { "http", 80 },
  { "https", 443 }
};

URI::URI()
    : isValid_(true)
    , port_(0)
{
}

URI::URI(const std::string &uri)
    : URI()
{
  parse(uri);
}

void URI::parse(const std::string &uri)
{
  std::smatch m;
  if (std::regex_search(uri, m, RE))
  {
    if (m.size() > 1)
    {
      scheme_ = m[1].str();
    }
    if (m.size() > 2)
    {
      std::vector<std::string> kv;
      const std::string &credentials = m[2].str();
      boost::split(kv, credentials, boost::is_any_of(":"));
      if (kv.size() == 2)
      {
        username_ = kv[0];
        password_ = kv[1];
      }
      else
      {
        isValid_ = false;
      }
    }
    if (m.size() > 3)
    {
      host_ = m[3].str();
    }
    if (m.size() > 4 && m[4].str().size() > 0)
    {
      port_ = std::stoi(m[4].str());
    }
    else if (schemeToPort.find(scheme_) != schemeToPort.end())
    {
      port_ = schemeToPort.at(scheme_);
    }
    if (m.size() > 5)
    {
      path_ = m[5].str();
    }
    if (m.size() > 7)
    {
      std::vector<std::string> kv;
      const std::string &p = m[7].str();
      boost::split(kv, p, boost::is_any_of("&"));
      for (const auto &param : kv)
      {
        std::vector<std::string> pair;
        boost::split(pair, param, boost::is_any_of("="));
        if (pair.size() == 2)
        {
          query_[pair.at(0)] = pair.at(1);
        }
        else
        {
          isValid_ = false;
        }
      }
    }
    if (m.size() > 8)
    {
      fragment_ = m[8].str();
    }
  }
}

void URI::parseTarget(const std::string &target)
{
  std::vector<std::string> pathAndQuery;
  boost::split(pathAndQuery, target, boost::is_any_of("?"));
  if (pathAndQuery.size() > 0)
  {
    path_ = pathAndQuery.at(0);
  }
  if (pathAndQuery.size() > 1)
  {
    std::vector<std::string> queryAndFragment;
    boost::split(queryAndFragment, pathAndQuery.at(1), boost::is_any_of("#"));
    if (queryAndFragment.size() > 0)
    {
      std::vector<std::string> kv;
      boost::split(kv, queryAndFragment.at(0), boost::is_any_of("&"));
      for (const auto &param : kv)
      {
        std::vector<std::string> pair;
        boost::split(pair, param, boost::is_any_of("="));
        if (pair.size() == 2)
        {
          query_[pair.at(0)] = pair.at(1);
        }
      }
    }
    if (queryAndFragment.size() > 1)
    {
      fragment_ = queryAndFragment.at(1);
    }
  }
}

