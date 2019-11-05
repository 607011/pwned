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

#include <regex>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <pwned-lib/hash.hpp>
#include <pwned-lib/passwordinspector.hpp>

#include "pwned-server.hpp"
#include "uri.hpp"
#include "fields_alloc.hpp"

namespace pt = boost::property_tree;
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using namespace detail;

class HttpWorker
{
public:
  HttpWorker(HttpWorker const &) = delete;
  HttpWorker& operator=(HttpWorker const &) = delete;

  HttpWorker(tcp::acceptor &acceptor, const std::string &basePath, const std::string &inputFilename, const std::string &indexFilename)
  : mAcceptor(acceptor)
  , mBasePath(basePath)
  , mInspector(inputFilename, indexFilename)
  {}

  void start()
  {
    accept();
    checkDeadline();
  }

private:
  using alloc_t = fields_alloc<char>;
  using request_body_t = http::string_body;

  tcp::acceptor &mAcceptor;
  std::string mBasePath;
  pwned::PasswordInspector mInspector;
  tcp::socket mSocket{mAcceptor.get_executor()};
  beast::flat_static_buffer<8192> mBuffer;
  alloc_t mAlloc{8192};
  boost::optional<http::request_parser<request_body_t, alloc_t>> mParser;
  boost::asio::basic_waitable_timer<std::chrono::steady_clock> mRequestDeadline{mAcceptor.get_executor(), (std::chrono::steady_clock::time_point::max)()};
  boost::optional<http::response<http::string_body, http::basic_fields<alloc_t>>> mStringResponse;
  boost::optional<http::response_serializer<http::string_body, http::basic_fields<alloc_t>>> mStringSerializer;

  void accept()
  {
    beast::error_code ec;
    mSocket.close(ec);
    mBuffer.consume(mBuffer.size());
    mAcceptor.async_accept(
      mSocket,
      [this](beast::error_code ec)
      {
        if (ec)
        {
          accept();
        }
        else
        {
          mRequestDeadline.expires_after(std::chrono::seconds(60));
          readRequest();
        }
      });
  }

  void readRequest()
  {
    mParser.emplace(
      std::piecewise_construct,
      std::make_tuple(),
      std::make_tuple(mAlloc));
    http::async_read(
      mSocket,
      mBuffer,
      *mParser,
      [this](beast::error_code ec, std::size_t)
      {
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

  void sendResponse(boost::beast::string_view target)
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
      const double duration = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count() * 1000;
      pt::ptree response;
      response.put<std::string>("hash", hash.toString());
      response.put<int>("found", phc.count);
      response.put<double>("lookup-time-ms", duration);
      mStringResponse.emplace(
        std::piecewise_construct,
        std::make_tuple(),
        std::make_tuple(mAlloc));
        mStringResponse->result(http::status::ok);
      mStringResponse->keep_alive(false);
      mStringResponse->set(http::field::server, "#pnwed server 1.0");
      mStringResponse->set(http::field::content_type, "application/json");
      mStringResponse->body() = toJson(response);
      mStringResponse->prepare_payload();
      mStringSerializer.emplace(*mStringResponse);
      http::async_write(
        mSocket,
        *mStringSerializer,
        [this](boost::beast::error_code ec, std::size_t)
        {
          mSocket.shutdown(tcp::socket::shutdown_send, ec);
          mStringSerializer.reset();
          mStringResponse.reset();
          accept();
        });
    }
    else
    {
      sendBadResponse(http::status::not_found, "");
    }
  }

  void processRequest(http::request<request_body_t, http::basic_fields<alloc_t>> const& req)
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

  void sendBadResponse(
      http::status status,
      std::string const& error)
  {
    mStringResponse.emplace(
      std::piecewise_construct,
      std::make_tuple(),
      std::make_tuple(mAlloc));
    mStringResponse->result(status);
    mStringResponse->keep_alive(false);
    mStringResponse->set(http::field::server, "Beast");
    mStringResponse->set(http::field::content_type, "text/plain");
    mStringResponse->body() = error;
    mStringResponse->prepare_payload();
    mStringSerializer.emplace(*mStringResponse);
    http::async_write(
        mSocket,
        *mStringSerializer,
        [this](beast::error_code ec, std::size_t)
        {
            mSocket.shutdown(tcp::socket::shutdown_send, ec);
            mStringSerializer.reset();
            mStringResponse.reset();
            accept();
        });
  }

  void checkDeadline()
  {
    if (mRequestDeadline.expiry() <= std::chrono::steady_clock::now())
    {
      beast::error_code ec;
      mSocket.close();
      mRequestDeadline.expires_at(std::chrono::steady_clock::time_point::max());
    }
    mRequestDeadline.async_wait(
      [this](beast::error_code)
      {
        checkDeadline();
      });
  }
};

#endif // __httpworker_hpp__
