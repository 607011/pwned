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

#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <cpprest/json.h>
#include <cpprest/uri.h>

#include "httpinspector.hpp"

HttpInspector::HttpInspector()
: inspector(nullptr)
{}

HttpInspector::HttpInspector(web::uri uri, pwned::PasswordInspector *inspector)
: listener(uri)
, inspector(inspector)
{
  listener.support(web::http::methods::GET, std::bind(&HttpInspector::handleGet, this, std::placeholders::_1));
}

pplx::task<void> HttpInspector::accept()
{
  return listener.open();
}

pplx::task<void> HttpInspector::shutdown()
{
  return listener.close();
}

void HttpInspector::handleGet(web::http::http_request message)
{
  std::cout << message.to_string() << std::endl;
  utility::string_t relativePath = web::uri::decode(message.relative_uri().path());
  std::vector<utility::string_t>  path = web::uri::split_path(relativePath);
  if (path.size() == 1 && path[0] == "lookup" && inspector != nullptr)
  {
    std::map<utility::string_t, utility::string_t> query = web::uri::split_query(web::uri::decode(message.request_uri().query()));
    const pwned::Hash hash = pwned::Hash::fromHex(query["hash"]);
    const auto &t0 = std::chrono::high_resolution_clock::now();
    const pwned::PasswordHashAndCount &phc = inspector->binsearch(hash);
    const auto &t1 = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count() * 1000;
    web::json::value response = web::json::value::object();
    response["hash"] = web::json::value::string(phc.hash.toString());
    response["found"] = web::json::value::number(phc.count);
    response["lookup-time-ms"] = web::json::value::number(duration);
    message.reply(web::http::status_codes::OK, response);
  }
  message.reply(web::http::status_codes::BadRequest);
}
