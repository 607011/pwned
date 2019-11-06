#include "session.hpp"
#include <iostream>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <random>
#include <fstream>
#include <vector>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/ssl.hpp>
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

Session::Session(
  net::io_context &ioc,
  ssl::context &ctx,
  const std::string &address,
  const std::string &inputFilename,
  unsigned int runtimeSecs,
  uint64_t id)
    : mResolver(net::make_strand(ioc))
    , mStream(net::make_strand(ioc))
    , mSSLStream(net::make_strand(ioc), ctx)
    , mAddress(address)
    , mRuntimeSecs(runtimeSecs)
    , mRequestCount(0)
    , mURI(address)
    , mInitialized(false)
    , mSSL(false)
{
  mSSL = mURI.scheme() == "https";
  mGen.seed(1 << id);
  mInputFile.open(inputFilename, std::ios::binary);
  mInputSize = boost::filesystem::file_size(inputFilename);
  mT0 = std::chrono::high_resolution_clock::now();
  mT1 = mT0 + std::chrono::seconds(static_cast<int>(mRuntimeSecs));
}

void Session::run()
{
  if (mSSL && !mInitialized)
  {
    if (!SSL_set_tlsext_host_name(mSSLStream.native_handle(), mURI.host().c_str()))
    {
      beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
      std::cerr << ec.message() << std::endl;
      return;
    }
    mInitialized = true;
  }
  const uint64_t pos = mGen() % mInputSize;
  const uint64_t idx = pos - pos % pwned::PHC::size;
  pwned::PasswordHashAndCount phc;
  phc.read(mInputFile, idx);
  mReq.version(11);
  mReq.method(http::verb::get);
  mReq.target(mURI.path() + "?hash=" + phc.hash.toStringLC());
  mReq.set(http::field::host, mURI.host());
  mReq.set(http::field::user_agent, "#pwned load test");
  mRTTt0 = std::chrono::high_resolution_clock::now();
  mResolver.async_resolve(
      mURI.host(),
      std::to_string(mURI.port()),
      beast::bind_front_handler(&Session::onResolve, this));
}

void Session::onResolve(beast::error_code ec, tcp::resolver::results_type results)
{
  if (ec)
    return fail(ec, "resolve");
  if (mSSL)
  {
    beast::get_lowest_layer(mSSLStream).expires_after(std::chrono::seconds(30));
    beast::get_lowest_layer(mSSLStream).async_connect(
        results,
        beast::bind_front_handler(&Session::onConnect, this));
  }
  else
  {
    mStream.expires_after(std::chrono::seconds(30));
    mStream.async_connect(results, beast::bind_front_handler(&Session::onConnect, this));
  }
}

void Session::onHandshake(beast::error_code ec)
{
  if (ec)
    return fail(ec, "handshake");
  beast::get_lowest_layer(mSSLStream).expires_after(std::chrono::seconds(30));
  http::async_write(
    mSSLStream,
    mReq,
    beast::bind_front_handler(&Session::onWrite, this));
}

void Session::onConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
{
  if (ec)
    return fail(ec, "connect");
  if (mSSL)
  {
    mSSLStream.async_handshake(
        ssl::stream_base::client,
        beast::bind_front_handler(&Session::onHandshake, this));
  }
  else
  {
    mStream.expires_after(std::chrono::seconds(30));
    http::async_write(
      mStream,
      mReq,
      beast::bind_front_handler(&Session::onWrite, this));
  }
}

void Session::onWrite(beast::error_code ec, std::size_t /*bytes_transferred*/)
{
  if (ec)
    return fail(ec, "write");
  if (mSSL)
  {
    http::async_read(
      mSSLStream,
      mBuffer,
      mRes,
      beast::bind_front_handler(&Session::onRead, this));
  }
  else
  {
    http::async_read(
      mStream,
      mBuffer,
      mRes,
      beast::bind_front_handler(&Session::onRead, this));
  }
}

void Session::onRead(beast::error_code ec, std::size_t /*bytes_transferred*/)
{
  if (ec)
    return fail(ec, "read");
  // std::cout << mRes << std::endl;
  const auto rtt = std::chrono::high_resolution_clock::now() - mRTTt0;
  std::cout << rtt.count() << std::endl;
  mRTT.push_back(rtt);
  ++mRequestCount;
  if (mSSL)
  {
    beast::get_lowest_layer(mSSLStream).expires_after(std::chrono::seconds(30));
    mSSLStream.async_shutdown(
      beast::bind_front_handler(&Session::onShutdown, this));
  }
  else
  {
    mStream.socket().shutdown(tcp::socket::shutdown_both, ec);
    if (ec && ec != beast::errc::not_connected)
      return fail(ec, "shutdown");
    restart();
  }
}

void Session::onShutdown(beast::error_code ec)
{
  if (ec == net::error::eof)
  {
    ec = {};
  }
  if (ec)
    return fail(ec, "shutdown");
  restart();
}

void Session::restart()
{
  if (std::chrono::high_resolution_clock::now() < mT1)
  {
    run();
  }
  else
  {
    mT1 = std::chrono::high_resolution_clock::now();
  }
}

uint64_t Session::requestCount() const
{
  return mRequestCount;
}

std::vector<std::chrono::nanoseconds> Session::rtts() const
{
  return mRTT;
}

std::chrono::nanoseconds Session::dt() const
{
  return mT1 - mT0;
}
