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
#include <regex>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <pwned-lib/hash.hpp>

#include "pwned-server.hpp"
#include "uri.hpp"
#include "httpworker.hpp"

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
    const std::string &indexFilename)
    : mAcceptor(acceptor), mBasePath(basePath), mInspector(inputFilename, indexFilename)
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

static std::string toJson(const pt::ptree &pt)
{
  std::ostringstream ss;
  pt::write_json(ss, pt);
  const std::regex re("\\\"([0-9]+\\.{0,1}[0-9]*)\\\"");
  return std::regex_replace(ss.str(), re, "$1");
}

void HttpWorker::processRequest(http::request<http::string_body> const &req)
{
  switch (req.method())
  {
  case http::verb::get:
    sendResponse(req.target());
    break;
  default:
    sendBadResponse(
        http::status::bad_request,
        "Invalid request method '" + std::string(req.method_string()) + "'\r\n");
    break;
  }
}

void HttpWorker::sendResponse(const boost::beast::string_view &target)
{
  URI uri;
  uri.parseTarget(target.to_string());
  const std::string &lookupPath = mBasePath + "/lookup";
  std::cout << std::chrono::high_resolution_clock::now().time_since_epoch().count() << " " << target.to_string() << std::endl;
  if (uri.path() == lookupPath && uri.query().find("hash") != uri.query().end())
  {
    const pwned::Hash &hash = pwned::Hash::fromHex(uri.query().at("hash"));
    const auto &t0 = std::chrono::high_resolution_clock::now();
    const pwned::PasswordHashAndCount &phc = mInspector.binsearch(hash);
    const auto &t1 = std::chrono::high_resolution_clock::now();
    const double duration = 1e3 * std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    pt::ptree response;
    response.put<std::string>("hash", hash.toString());
    response.put<int>("found", phc.count);
    constexpr int BufSize = 20;
    char buf[BufSize];
    std::snprintf(buf, BufSize, "%.5f", duration);
    response.put<char *>("lookup-time-ms", buf);
    mResponse.emplace();
    mResponse->result(http::status::ok);
    mResponse->set(http::field::server, std::string("#pnwed server ") + PWNED_SERVER_VERSION);
    mResponse->set(http::field::content_type, "application/json");
    mResponse->body() = toJson(response);
    mResponse->prepare_payload();
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
  mResponse->set(http::field::server, std::string("#pnwed server ") + PWNED_SERVER_VERSION);
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
    beast::error_code ec;
    mSocket.close();
    mReqTimeout.expires_at(std::chrono::steady_clock::time_point::max());
  }
  mReqTimeout.async_wait(
      [this](beast::error_code) {
        checkTimeout();
      });
}

}
