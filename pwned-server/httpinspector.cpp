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


// #include <cpprest/asyncrt_utils.h>
#include <cpprest/json.h>
#include <cpprest/uri.h>

#include "httpinspector.hpp"

HttpInspector::HttpInspector(web::uri uri)
: listener(uri)
{
  listener.support(web::http::methods::GET, std::bind(&HttpInspector::handleGet, this, std::placeholders::_1));
}

void HttpInspector::handleGet(web::http::http_request message)
{
  std::cout << message.to_string() << std::endl;
  auto relativePath = web::uri::decode(message.relative_uri().path());
  auto path = web::uri::split_path(relativePath);
  message.reply(web::http::status_codes::OK);
}

pplx::task<void> HttpInspector::open()
{
  return listener.open();
}

pplx::task<void> HttpInspector::close()
{
  return listener.close();
}
