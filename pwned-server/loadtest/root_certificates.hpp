//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef __BOOST_BEAST_EXAMPLE_COMMON_ROOT_CERTIFICATES_HPP__
#define __BOOST_BEAST_EXAMPLE_COMMON_ROOT_CERTIFICATES_HPP__

#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>

namespace ssl = boost::asio::ssl;

void load_root_certificates(boost::asio::ssl::context &ctx, boost::system::error_code &ec);
void load_root_certificates(boost::asio::ssl::context &ctx);

#endif // __BOOST_BEAST_EXAMPLE_COMMON_ROOT_CERTIFICATES_HPP__
