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

#ifndef __session_hpp__
#define __session_hpp__

#include <cstdlib>
#include <string>
#include <random>
#include <vector>
#include <chrono>
#include <memory>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <pwned-lib/hash.hpp>
#include <pwned-lib/passwordhashandcount.hpp>

#include "../uri.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;

using tcp = boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session>
{
  net::io_context &mIoc;
  ssl::context &mCtx;
  tcp::resolver mResolver;
  beast::tcp_stream mStream;
  beast::ssl_stream<beast::tcp_stream> mSSLStream;
  beast::flat_buffer mBuffer;
  http::request<http::empty_body> mReq;
  http::response<http::string_body> mRes;
  std::string mAddress;
  std::mt19937_64 mGen;
  std::chrono::time_point<std::chrono::high_resolution_clock> mT0;
  std::chrono::time_point<std::chrono::high_resolution_clock> mT1;
  std::ifstream mInputFile;
  uint64_t mInputSize;
  pwned::Hash mQueriedHash;
  int mRuntimeSecs;
  uint64_t mRequestCount;
  std::chrono::time_point<std::chrono::high_resolution_clock> mRTTt0;
  std::vector<std::chrono::nanoseconds> mRTT;
  URI mURI;
  bool mSSL;

public:
  Session() = delete;
  Session(
    net::io_context& ioc,
    ssl::context &ctx,
    const std::string &address,
    const std::string &inputFilename,
    int runtimeSecs,
    int id);
  void run();
  void onResolve(beast::error_code ec, tcp::resolver::results_type results);
  void onConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type);
  void onWrite(beast::error_code ec, std::size_t /*bytes_transferred*/);
  void onRead(beast::error_code ec, std::size_t /*bytes_transferred*/);
  void onHandshake(beast::error_code ec);
  void onShutdown(beast::error_code ec);
  void restart();
  uint64_t requestCount() const;
  std::vector<std::chrono::nanoseconds> rtts() const;
  std::chrono::nanoseconds dt() const;

  static const int ExpiresAfterSecs = 30;
};

#endif // __session_hpp__
