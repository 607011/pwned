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

#include <iostream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>

#include <pwned-lib/hash.hpp>

#include "pwned-server.hpp"
#include "uri.hpp"
#include "httpworker.hpp"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

namespace webservice {

HttpWorker::HttpWorker(
    tcp::acceptor &acceptor,
    const std::string &basePath,
    const std::string &inputFilename,
    const std::string &indexFilename,
    log_callback_t *logCallback)
    : mAcceptor(acceptor)
    , mBasePath(basePath)
    , mInspector(inputFilename, indexFilename)
    , mLogCallback(logCallback)
    , mLastUpdated(fs::last_write_time(fs::path(inputFilename)))
{
}

void HttpWorker::start()
{
  accept();
  checkTimeout();
}

void HttpWorker::accept()
{
  beast::error_code ec;
  mSocket.close(ec);
  mBuffer.consume(mBuffer.size());
  mAcceptor.async_accept(
      mSocket,
      [this](beast::error_code ec) {
        if (ec)
        {
          accept();
        }
        else
        {
          mReqTimeout.expires_after(Timeout);
          readRequest();
        }
      });
}

void HttpWorker::readRequest()
{
  mParser.emplace();
  http::async_read(
      mSocket,
      mBuffer,
      *mParser,
      [this](beast::error_code ec, std::size_t) {
        if (ec)
        {
          accept();
        }
        else
        {
          processRequest(mParser->get());
        }
      });
}

void HttpWorker::processRequest(http::request<http::string_body> const &req)
{
  switch (req.method())
  {
  case http::verb::get:
    sendResponse(req);
    break;
  default:
    sendBadResponse(
        http::status::bad_request,
        "Invalid request method '" + std::string(req.method_string()) + "'\r\n");
    break;
  }
}

#include <ctime>
template<typename Clock, typename Duration>
std::ostream &operator<<(std::ostream &stream, const std::chrono::time_point<Clock, Duration> &time_point)
{
  const time_t time = Clock::to_time_t(time_point);
#if __GNUC__ > 4 || ((__GNUC__ == 4) && __GNUC_MINOR__ > 8 && __GNUC_REVISION__ > 1)
  struct tm tm;
  localtime_r(&time, &tm);
  return stream << std::put_time(&tm, "%c");
#else
  char buffer[26];
  ctime_r(&time, buffer);
  buffer[24] = '\0';
  return stream << buffer;
#endif
}

void makeResponse(boost::optional<http::response<http::string_body>> &response, const std::string &msg)
{
  response.emplace();
  response->result(http::status::ok);
  response->set(http::field::server, std::string("#pwned server ") + PWNED_SERVER_VERSION);
  response->set(http::field::content_type, "application/json");
  response->set("Access-Control-Allow-Origin", "*");
  response->body() = msg;
  response->prepare_payload();
}

void HttpWorker::sendResponse(http::request<http::string_body> const &req)
{
  URI uri;
  uri.parseTarget(req.target().to_string());
  if (mLogCallback != nullptr)
  {
    std::ostringstream ss;
    ss << std::chrono::system_clock::now() << ' '
       << mSocket.remote_endpoint().address().to_string() << ' '
       << req.target().to_string();
    (*mLogCallback)(ss.str());
  }
  if (uri.path() == (mBasePath + "/lookup") && uri.query().find("hash") != uri.query().end())
  {
    const pwned::Hash &hash = pwned::Hash::fromHex(uri.query().at("hash"));
    const auto &t0 = std::chrono::high_resolution_clock::now();
    const pwned::PasswordHashAndCount &phc = mInspector.binsearch(hash);
    const auto &t1 = std::chrono::high_resolution_clock::now();
    const double duration = 1e3 * std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    pt::ptree response;
    response.put<std::string>("hash", hash.toString());
    response.put<std::string>("found", "[found]");
    response.put<std::string>("lookup-time-ms", "[lookup-time-ms]");
    std::ostringstream ss;
    pt::write_json(ss, response, false);
    std::string responseStr = ss.str();
    boost::replace_all<std::string>(responseStr, std::string("\"[found]\""), std::to_string(phc.count));
    boost::replace_all<std::string>(responseStr, std::string("\"[lookup-time-ms]\""), std::to_string(duration));
    makeResponse(mResponse, responseStr);
    mSerializer.emplace(*mResponse);
    http::async_write(
        mSocket,
        *mSerializer,
        [this](boost::beast::error_code ec, std::size_t) {
          mSocket.shutdown(tcp::socket::shutdown_send, ec);
          mSerializer.reset();
          mResponse.reset();
          accept();
        });
  }
  else if (uri.path() == (mBasePath + "/info"))
  {
    pt::ptree response;
    response.put<std::string>("count", "[count]");
    response.put<std::string>("last-update", "[last-update]");
    std::ostringstream ss;
    pt::write_json(ss, response, false);
    std::string responseStr = ss.str();
    boost::replace_all<std::string>(responseStr, std::string("\"[count]\""), std::to_string(mInspector.size()));
    boost::replace_all<std::string>(responseStr, std::string("\"[last-update]\""), std::to_string(mLastUpdated));
    makeResponse(mResponse, responseStr);
    mSerializer.emplace(*mResponse);
    http::async_write(
        mSocket,
        *mSerializer,
        [this](boost::beast::error_code ec, std::size_t) {
          mSocket.shutdown(tcp::socket::shutdown_send, ec);
          mSerializer.reset();
          mResponse.reset();
          accept();
        });
  }
  else
  {
    sendBadResponse(http::status::not_found, "");
  }
}

void HttpWorker::sendBadResponse(http::status status, const std::string &error)
{
  mResponse.emplace();
  mResponse->result(status);
  mResponse->set(http::field::server, std::string("#pwned server ") + PWNED_SERVER_VERSION);
  mResponse->set(http::field::content_type, "text/plain");
  mResponse->body() = error;
  mResponse->prepare_payload();
  mSerializer.emplace(*mResponse);
  http::async_write(
      mSocket,
      *mSerializer,
      [this](beast::error_code ec, std::size_t) {
        mSocket.shutdown(tcp::socket::shutdown_send, ec);
        mSerializer.reset();
        mResponse.reset();
        accept();
      });
}

void HttpWorker::checkTimeout()
{
  if (mReqTimeout.expiry() <= std::chrono::steady_clock::now())
  {
    mSocket.close();
    mReqTimeout.expires_at(std::chrono::steady_clock::time_point::max());
  }
  mReqTimeout.async_wait(
      [this](beast::error_code) {
        checkTimeout();
      });
}

}
