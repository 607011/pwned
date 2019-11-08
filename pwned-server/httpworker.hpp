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

#ifndef __httpworker_hpp__
#define __httpworker_hpp__

#include <string>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/optional.hpp>

#include <pwned-lib/passwordinspector.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

class HttpWorker
{
public:
  HttpWorker(HttpWorker const &) = delete;
  HttpWorker& operator=(HttpWorker const &) = delete;
  HttpWorker(
      tcp::acceptor &acceptor,
      const std::string &basePath,
      const std::string &inputFilename,
      const std::string &indexFilename);
  void start();

private:
  using alloc_t = std::allocator<char>;
  tcp::acceptor &mAcceptor;
  std::string mBasePath;
  pwned::PasswordInspector mInspector;
  tcp::socket mSocket{mAcceptor.get_executor()};
  beast::flat_buffer mBuffer;
  alloc_t mAlloc;
  boost::optional<http::request_parser<http::string_body>> mParser;
  boost::asio::basic_waitable_timer<std::chrono::steady_clock> mRequestDeadline{mAcceptor.get_executor(), (std::chrono::steady_clock::time_point::max)()};
  boost::optional<http::response<http::string_body, http::basic_fields<alloc_t>>> mStringResponse;
  boost::optional<http::response_serializer<http::string_body, http::basic_fields<alloc_t>>> mStringSerializer;

  void accept();
  void readRequest();
  void sendResponse(boost::beast::string_view target);
  void processRequest(http::request<http::string_body, http::basic_fields<alloc_t>> const &req);
  void sendBadResponse(http::status status, std::string const &error);
  void checkDeadline();
};

#endif // __httpworker_hpp__
