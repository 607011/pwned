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
#include <fstream>
#include <string>
#include <chrono>

#include <boost/program_options.hpp>
#include <boost/asio.hpp>

#include "httpinspector.hpp"

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/time.h>
#endif

namespace po = boost::program_options;

po::options_description desc("Allowed options");

std::unique_ptr<HttpInspector> gHttpInspector;


boost::asio::ip::tcp::resolver::iterator queryHostInetInfo() {
  boost::asio::io_service ios;
  boost::asio::ip::tcp::resolver resolver(ios);
  boost::asio::ip::tcp::resolver::query query(boost::asio::ip::host_name(), "");
  return resolver.resolve(query);
}

std::string hostIP(unsigned short family)
{
  auto hostInetInfo = queryHostInetInfo();
  boost::asio::ip::tcp::resolver::iterator end;
  while(hostInetInfo != end) {
    boost::asio::ip::tcp::endpoint ep = *hostInetInfo++;
    sockaddr sa = *ep.data();
    if (sa.sa_family == family) {
      return ep.address().to_string();
    }
  }
  return nullptr;
}

inline std::string hostIP4()
{
  return hostIP(AF_INET);
}

inline std::string hostIP6()
{
  return hostIP(AF_INET6);
}


void hello()
{
  std::cout << "#pwned server - Copyright (c) 2019 Oliver Lau" << std::endl
            << std::endl;
}

void license()
{
  std::cout << "This program comes with ABSOLUTELY NO WARRANTY; for details type" << std::endl
            << "`pwned-server --warranty'." << std::endl
            << "This is free software, and you are welcome to redistribute it" << std::endl
            << "under certain conditions; see https://www.gnu.org/licenses/gpl-3.0.en.html" << std::endl
            << "for details." << std::endl
            << std::endl;
}

void warranty()
{
  std::cout << "Warranty info:" << std::endl
            << std::endl
            << "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION." << std::endl
            << std::endl
            << "IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES." << std::endl
            << std::endl;
}

void usage()
{
  std::cout << desc << std::endl;
}

int main(int argc, const char *argv[])
{
  static const std::string DefaultURI = "http://127.0.0.1:31337/v1/pwned/api";
  std::string inputFilename;
  std::string indexFilename;
  std::string endpoint = DefaultURI;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set MD5:count input file")
  ("index,X", po::value<std::string>(&indexFilename), "set index file")
  ("address", po::value<std::string>(&endpoint)->default_value(DefaultURI), "server URI")
  ("warranty", "display warranty information")
  ("license", "display license information");
  po::variables_map vm;
  try
  {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  }
  catch (po::error &e)
  {
    std::cerr << "ERROR: " << e.what() << std::endl
              << std::endl;
    usage();
    return EXIT_FAILURE;
  }
  po::notify(vm);
  if (inputFilename.empty())
  {
    std::cerr << "ERROR: input file not given." << std::endl;
    usage();
    return EXIT_FAILURE;
  }

  hello();
  pwned::PasswordInspector *inspector = new pwned::PasswordInspector(inputFilename, indexFilename);

  web::uri endpointURI(endpoint);
  web::uri_builder endpointBuilder;
  endpointBuilder.set_scheme(endpointURI.scheme());
  if (endpointURI.host() == "host_auto_ip4")
  {
    endpointBuilder.set_host(hostIP4());        
  }
  else if (endpointURI.host() == "host_auto_ip6")
  {
    endpointBuilder.set_host(hostIP6());
  }
  else
  {
    endpointBuilder.set_host(endpointURI.host());
  }
  endpointBuilder.set_port(endpointURI.port());
  endpointBuilder.set_path(endpointURI.path());
  
  gHttpInspector = std::unique_ptr<HttpInspector>(new HttpInspector(endpointBuilder.to_uri(), inspector));

  try {
    gHttpInspector->accept().wait();
    std::cout << "Listening for requests at " << endpointBuilder.to_string() << " ... " << std::endl;
  }
  catch (std::exception & e)
  {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "ERROR: unknown cause :-(" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "Press ENTER to exit." << std::endl;
  std::string line;
  std::getline(std::cin, line);

  gHttpInspector->shutdown().wait();
  delete inspector;

  return EXIT_SUCCESS;
}
