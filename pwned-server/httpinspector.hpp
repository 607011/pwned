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

#ifndef __HTTPINSPECTOR_HPP__
#define __HTTPINSPECTOR_HPP__

#include <cpprest/http_listener.h>

class HttpInspector
{
public:
  HttpInspector() = default;
  HttpInspector(web::uri uri);

  pplx::task<void> open();
  pplx::task<void> close();

private:
  void handleGet(web::http::http_request message);
  web::http::experimental::listener::http_listener listener;
};

#endif
