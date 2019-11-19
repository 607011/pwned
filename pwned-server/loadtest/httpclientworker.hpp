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

#ifndef __httpclientworker_hpp__
#define __httpclientworker_hpp__

#include <cstdint>
#include <string>
#include <random>
#include <vector>
#include <chrono>
#include <memory>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional/optional.hpp>

#include "../uri.hpp"

class HttpClientWorker
{
public:
  typedef std::chrono::time_point<std::chrono::steady_clock> clock_type;
  HttpClientWorker() = delete;
  HttpClientWorker(
    boost::asio::io_context& ioc,
    boost::asio::ssl::context &ctx,
    const std::string &address,
    const std::string &inputFilename,
    int runtimeSecs,
    int id);
  void start();
  void onResolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
  void connect();
  void onConnect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type);
  void onWrite(boost::beast::error_code ec, size_t bytesTransferred);
  void onRead(boost::beast::error_code ec, size_t bytesTransferred);
  void onHandshake(boost::beast::error_code ec);
  void onShutdown(boost::beast::error_code ec);
  void restart();
  uint64_t requestCount() const;
  std::vector<std::chrono::nanoseconds> rtts() const;
  std::chrono::nanoseconds dt() const;
  const clock_type &t0() const;
  const clock_type &t1() const;
  const clock_type &tStop() const;

  static const int ExpiresAfterSecs;

private:
  boost::asio::io_context &mIoc;
  boost::asio::ssl::context &mCtx;
  boost::asio::ip::tcp::resolver mResolver;
  boost::asio::ip::tcp::resolver::results_type mResolverResults;
  boost::beast::tcp_stream mStream;
  boost::optional<boost::beast::ssl_stream<boost::beast::tcp_stream>> mSSLStream;
  boost::beast::flat_buffer mBuffer;
  boost::beast::http::request<boost::beast::http::empty_body> mReq;
  boost::beast::http::response<boost::beast::http::string_body> mRes;
  std::mt19937_64 mGen;
  std::ifstream mInputFile;
  uint64_t mInputSize;
  clock_type mT0;
  clock_type mT1;
  clock_type mTStop;
  uint64_t mRequestCount{0};
  clock_type mRTTt0;
  std::vector<std::chrono::nanoseconds> mRTT;
  URI mURI;
};

#endif // __httpclientworker_hpp__
