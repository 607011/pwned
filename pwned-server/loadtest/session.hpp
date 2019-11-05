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

#include <iostream>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <random>
#include <fstream>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/filesystem.hpp>

#include <pwned-lib/passwordhashandcount.hpp>

#include "../uri.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

static void fail(beast::error_code ec, char const *what)
{
  std::cerr << what << ": " << ec.message() << "\n";
}

class Session
{
  tcp::resolver mResolver;
  beast::tcp_stream mStream;
  beast::flat_buffer mBuffer; // (Must persist between reads)
  http::request<http::empty_body> mReq;
  http::response<http::string_body> mRes;
  std::string mAddress;
  std::mt19937_64 mGen;
  std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds> mT0;
  std::chrono::time_point<std::chrono::system_clock, std::chrono::nanoseconds> mT1;
  std::ifstream mInputFile;
  uint64_t mInputSize;
  unsigned int mRuntimeSecs;
  uint64_t mId;
  uint64_t mRequests;

public:
  explicit Session(net::io_context& ioc, const std::string &address, const std::string &inputFilename, unsigned int runtimeSecs, uint64_t id)
      : mResolver(net::make_strand(ioc))
      , mStream(net::make_strand(ioc))
      , mAddress(address)
      , mRuntimeSecs(runtimeSecs)
      , mId(id)
      , mRequests(0)
  {
    mGen.seed(id);
    mInputFile.open(inputFilename, std::ios::binary);
    mInputSize = boost::filesystem::file_size(inputFilename);
    mT0 = std::chrono::high_resolution_clock::now();
    mT1 = mT0 + std::chrono::seconds(static_cast<int>(mRuntimeSecs));
  }

  void run()
  {
    URI uri(mAddress);
    pwned::PasswordHashAndCount phc;
    const uint64_t pos = mGen() % mInputSize;
    const uint64_t idx = pos - pos % pwned::PHC::size;
    phc.read(mInputFile, idx);
    mReq.version(11);
    mReq.method(http::verb::get);
    mReq.target(uri.path() + "?hash=" + phc.hash.toStringLC());
    mReq.set(http::field::host, uri.host());
    mReq.set(http::field::user_agent, "#pwned load test");
    // std::cout << "#" << mId << ": " << mReq.target() << std::endl;
    mResolver.async_resolve(
      uri.host(),
      std::to_string(uri.port()),
      beast::bind_front_handler(&Session::onResolve, this));
  }

  void onResolve(beast::error_code ec, tcp::resolver::results_type results)
  {
    if (ec)
      return fail(ec, "resolve");
    mStream.expires_after(std::chrono::seconds(30));
    mStream.async_connect(
      results,
      beast::bind_front_handler(&Session::onConnect, this));
  }

  void onConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
  {
    if (ec)
      return fail(ec, "connect");
    mStream.expires_after(std::chrono::seconds(30));
    http::async_write(mStream, mReq,
      beast::bind_front_handler(&Session::onWrite, this));
  }

  void onWrite(beast::error_code ec, std::size_t /*bytes_transferred*/)
  {
    if (ec)
      return fail(ec, "write");
    http::async_read(mStream, mBuffer, mRes,
      beast::bind_front_handler(&Session::onRead, this));
  }

  void onRead(beast::error_code ec, std::size_t /*bytes_transferred*/)
  {
    if (ec)
      return fail(ec, "read");
    // std::cout << mRes << std::endl;
    mStream.socket().shutdown(tcp::socket::shutdown_both, ec);
    if (ec && ec != beast::errc::not_connected)
      return fail(ec, "shutdown");
    ++mRequests;
    if (std::chrono::high_resolution_clock::now() < mT1)
    {
      run();
    }
  }

  uint64_t requests() const
  {
    return mRequests;
  }
};

#endif // __session_hpp__
