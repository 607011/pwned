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
#include <memory>
#include <exception>
#include <sstream>
#include <list>

#include <boost/program_options.hpp>

#include "pwned-server.hpp"
#include "uri.hpp"
#include "httpworker.hpp"

namespace po = boost::program_options;
using tcp = boost::asio::ip::tcp;

void hello()
{
  std::cout << "#pwned server " << PWNED_SERVER_VERSION << " - Copyright (c) 2019 Oliver Lau" << std::endl;
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

po::options_description desc("Allowed options");

void usage()
{
  std::cout << desc << std::endl;
}

int main(int argc, const char *argv[])
{
  static const std::string DefaultAddress = "http://127.0.0.1:31337/v1/pwned/api";
  static const int DefaultNumWorkers = 4;
  std::string inputFilename;
  std::string indexFilename;
  std::string address;
  int numWorkers = 4;
  desc.add_options()
  ("help", "produce help message")
  ("input,I", po::value<std::string>(&inputFilename), "set MD5:count input file")
  ("index,X", po::value<std::string>(&indexFilename), "set index file")
  ("address", po::value<std::string>(&address)->default_value(DefaultAddress), "server address")
  ("threads", po::value<int>(&numWorkers)->default_value(DefaultNumWorkers), "number of worker threads")
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

  if (numWorkers < 1)
  {
    std::cout << "WARNING: Illegal number of workers given. Defaulting to " << DefaultNumWorkers << std::endl;
    numWorkers = DefaultNumWorkers;
  }

  try
  {
    URI uri(address);
    boost::asio::io_context ioc{numWorkers};
    tcp::acceptor acceptor{ioc, {boost::asio::ip::make_address(uri.host()), uri.port()}};
    std::list<HttpWorker> workers;
    for (int i = 0; i < numWorkers; ++i)
    {
      workers.emplace_back(acceptor, uri.path(), inputFilename, indexFilename);
      workers.back().start();
    }
    std::cout << numWorkers << " workers listening on " << uri.host() << ':' << uri.port() << " ..." << std::endl;
    boost::system::error_code ec;
    ioc.run(ec);
    if (ec)
    {
      std::cerr << "Error: " << ec.message() << std::endl;
    }
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
