//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#include <string>

#include "root_certificates.hpp"
#include "root_certificates_generated.hpp"

namespace ssl = boost::asio::ssl;

void load_root_certificates(ssl::context &ctx, boost::system::error_code &ec)
{
  const std::string cert(ROOT_CERTIFICATES);
  ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
}

void load_root_certificates(ssl::context &ctx)
{
  boost::system::error_code ec;
  load_root_certificates(ctx, ec);
  if (ec)
    throw boost::system::system_error{ec};
}
