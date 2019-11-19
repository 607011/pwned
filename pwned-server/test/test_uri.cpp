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

#define BOOST_TEST_MODULE test uri
#define BOOST_TEST_MODULE_URI

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstring>
#include <boost/test/unit_test.hpp>
#include "../uri.hpp"

BOOST_AUTO_TEST_SUITE(test_uri)

BOOST_AUTO_TEST_CASE(test_uri_ctor)
{
  {
    URI uri("http://localhost/");
    BOOST_TEST(uri.scheme() == "http");
    BOOST_TEST(uri.username() == "");
    BOOST_TEST(uri.password() == "");
    BOOST_TEST(uri.host() == "localhost");
    BOOST_TEST(uri.port() == 80);
    BOOST_TEST(uri.path() == "/");
    BOOST_TEST(uri.query().size() == 0);
    BOOST_TEST(uri.fragment() == "");
  }
  {
    URI uri("https://localhost/");
    BOOST_TEST(uri.scheme() == "https");
    BOOST_TEST(uri.port() == 443);
  }
  {
    URI uri("https://127.0.0.1/");
    BOOST_TEST(uri.host() == "127.0.0.1");
  }
  {
    URI uri("https://127.0.0.1/test");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/test");
  }
  {
    URI uri("https://127.0.0.1/foo/bar");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar");
  }
  {
    URI uri("https://127.0.0.1/foo/bar/baz");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz?a=1");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
    BOOST_TEST(uri.query().size() == 1);
    BOOST_TEST(uri.query().at("a") == "1");
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz&a=1");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz&a=1");
    BOOST_TEST(uri.query().size() == 0);
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz?a=1&bb=22");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
    BOOST_TEST(uri.query().size() == 2);
    BOOST_TEST(uri.query().at("a") == "1");
    BOOST_TEST(uri.query().at("bb") == "22");
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz?a=1?b=2");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
    BOOST_TEST(uri.query().size() == 0);
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz?a=1&bb=22&ccc=333#fragment");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
    BOOST_TEST(uri.query().size() == 3);
    BOOST_TEST(uri.fragment() == "fragment");
  }
  {
    URI uri("https://user:12345@127.0.0.1/foo/bar/baz?#fragment");
    BOOST_TEST(uri.username() == "user");
    BOOST_TEST(uri.password() == "12345");
    BOOST_TEST(uri.host() == "127.0.0.1");
    BOOST_TEST(uri.path() == "/foo/bar/baz");
    BOOST_TEST(uri.query().size() == 0);
    BOOST_TEST(uri.fragment() == "fragment");
  }
  {
    URI uri("ftp://foo:bar@example.com/");
    BOOST_TEST(uri.scheme() == "ftp");
    BOOST_TEST(uri.username() == "foo");
    BOOST_TEST(uri.password() == "bar");
  }
}

BOOST_AUTO_TEST_SUITE_END()
