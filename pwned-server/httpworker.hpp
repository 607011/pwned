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
#include <chrono>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/optional/optional.hpp>

#include <pwned-lib/passwordinspector.hpp>

class HttpWorker
{
public:
  HttpWorker(HttpWorker const &) = delete;
  HttpWorker& operator=(HttpWorker const &) = delete;
  HttpWorker(
      boost::asio::ip::tcp::acceptor &acceptor,
      const std::string &basePath,
      const std::string &inputFilename,
      const std::string &indexFilename);
  void start();

  static constexpr std::chrono::seconds Timeout{60};

private:
  using alloc_t = std::allocator<char>;
  boost::asio::ip::tcp::acceptor &mAcceptor;
  std::string mBasePath;
  pwned::PasswordInspector mInspector;
  boost::asio::ip::tcp::socket mSocket{mAcceptor.get_executor()};
  boost::beast::flat_buffer mBuffer;
  alloc_t mAlloc;
  boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> mParser;
  boost::asio::basic_waitable_timer<std::chrono::steady_clock> mReqTimeout{mAcceptor.get_executor(), (std::chrono::steady_clock::time_point::max)()};
  boost::optional<boost::beast::http::response<boost::beast::http::string_body, boost::beast::http::basic_fields<alloc_t>>> mResponse;
  boost::optional<boost::beast::http::response_serializer<boost::beast::http::string_body, boost::beast::http::basic_fields<alloc_t>>> mSerializer;

  void accept();
  void readRequest();
  void sendResponse(boost::beast::string_view target);
  void processRequest(boost::beast::http::request<boost::beast::http::string_body, boost::beast::http::basic_fields<alloc_t>> const &req);
  void sendBadResponse(boost::beast::http::status status, const std::string &error);
  void checkTimeout();
};

#endif // __httpworker_hpp__
