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
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <pwned-lib/passwordhashandcount.hpp>

#include "../uri.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace pt = boost::property_tree;
using tcp = boost::asio::ip::tcp;

static void fail(const beast::error_code &ec, char const *what)
{
  std::cerr << what << ": " << ec.message() << " #" << ec.value() << std::endl;
}

Session::Session(
  net::io_context &ioc,
  ssl::context &ctx,
  const std::string &address,
  const std::string &inputFilename,
  int runtimeSecs,
  int id)
    : mIoc(ioc)
    , mCtx(ctx)
    , mResolver(net::make_strand(ioc))
    , mStream(net::make_strand(ioc))
    , mSSLStream(net::make_strand(ioc), ctx)
    , mAddress(address)
    , mRuntimeSecs(runtimeSecs)
    , mRequestCount(0)
    , mURI(address)
    , mSSL(false)
{
  mSSL = mURI.scheme() == "https";
  mGen.seed(static_cast<uint64_t>(id));
  mInputSize = boost::filesystem::file_size(inputFilename);
  mInputFile.open(inputFilename, std::ios::binary);
  mT0 = std::chrono::high_resolution_clock::now();
  mT1 = mT0 + std::chrono::seconds(mRuntimeSecs);
}

void Session::run()
{
  if (mSSL)
  {
    if (!SSL_set_tlsext_host_name(mSSLStream.native_handle(), mURI.host().c_str()))
    {
      beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
      std::cerr << ec.message() << std::endl;
      return;
    }
  }
  const uint64_t pos = mGen() % mInputSize;
  const uint64_t idx = pos - pos % pwned::PHC::size;
  pwned::PasswordHashAndCount phc;
  phc.read(mInputFile, idx);
  mQueriedHash = phc.hash;
  mReq.version(11);
  mReq.method(http::verb::get);
  mReq.target(mURI.path() + "?hash=" + mQueriedHash.toStringLC());
  mReq.set(http::field::host, mURI.host());
  mReq.set(http::field::user_agent, "#pwned load test");
  mRTTt0 = std::chrono::high_resolution_clock::now();
  mResolver.async_resolve(
      mURI.host(),
      std::to_string(mURI.port()),
      beast::bind_front_handler(&Session::onResolve, shared_from_this()));
}

void Session::onResolve(beast::error_code ec, tcp::resolver::results_type results)
{
  if (ec)
    return fail(ec, "resolve");
  if (mSSL)
  {
    beast::get_lowest_layer(mSSLStream).expires_after(std::chrono::seconds(ExpiresAfterSecs));
    beast::get_lowest_layer(mSSLStream).async_connect(
        results,
        beast::bind_front_handler(&Session::onConnect, shared_from_this()));
  }
  else
  {
    mStream.expires_after(std::chrono::seconds(ExpiresAfterSecs));
    mStream.async_connect(results, beast::bind_front_handler(&Session::onConnect, shared_from_this()));
  }
}

void Session::onConnect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
{
  if (ec)
    return fail(ec, "connect");
  if (mSSL)
  {
    mSSLStream.async_handshake(
        ssl::stream_base::client,
        beast::bind_front_handler(&Session::onHandshake, shared_from_this()));
  }
  else
  {
    mStream.expires_after(std::chrono::seconds(ExpiresAfterSecs));
    http::async_write(
      mStream,
      mReq,
      beast::bind_front_handler(&Session::onWrite, shared_from_this()));
  }
}

void Session::onHandshake(beast::error_code ec)
{
  if (ec)
    return fail(ec, "handshake");
  beast::get_lowest_layer(mSSLStream).expires_after(std::chrono::seconds(ExpiresAfterSecs));
  http::async_write(
    mSSLStream,
    mReq,
    beast::bind_front_handler(&Session::onWrite, shared_from_this()));
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
      beast::bind_front_handler(&Session::onRead, shared_from_this()));
  }
  else
  {
    http::async_read(
      mStream,
      mBuffer,
      mRes,
      beast::bind_front_handler(&Session::onRead, shared_from_this()));
  }
}

void Session::onRead(beast::error_code ec, std::size_t /*bytes_transferred*/)
{
  if (ec)
    return fail(ec, "read");
  const std::string &resStr = mRes.body().data();
  std::cout << mRes << std::endl;
  pt::ptree res;
  boost::iostreams::array_source as(&resStr[0], resStr.size());
  boost::iostreams::stream<boost::iostreams::array_source> is(as);
  try
  {
    pt::read_json(is, res);
  }
  catch(const std::exception &e)
  {
    std::cerr << "ERROR in read_json(): " << e.what() << std::endl;
    return;
  }
  const auto rtt = std::chrono::high_resolution_clock::now() - mRTTt0;
  mRTT.push_back(rtt);
  ++mRequestCount;
  if (mSSL)
  {
    beast::get_lowest_layer(mSSLStream).expires_after(std::chrono::seconds(ExpiresAfterSecs));
    mSSLStream.async_shutdown(
      beast::bind_front_handler(&Session::onShutdown, shared_from_this()));
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
  if (ec == net::error::eof || ec == net::ssl::error::stream_truncated)
  {
    ec = {};
  }
  if (ec)
    return fail(ec, "shutdown");
  restart();
}

void Session::restart()
{
  const auto now = std::chrono::high_resolution_clock::now();
  mRes.clear();
  mRes.body().clear();
  if (now < mT1)
  {
    if (mSSL)
    {
      // boost::beast::ssl_stream cannot be reused (https://github.com/boostorg/beast/issues/821#issuecomment-338354949)
      mSSLStream = boost::beast::ssl_stream<boost::beast::tcp_stream>(net::make_strand(mIoc), mCtx);
    }
    run();
  }
  else
  {
    mT1 = now;
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
