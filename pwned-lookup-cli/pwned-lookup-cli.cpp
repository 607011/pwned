/*
 Copyright © 2019 Oliver Lau <oliver@ersatzworld.net>

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
#include <iomanip>
#include <fstream>
#include <string>
#include <chrono>

#include <passwordinspector.hpp>

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void setStdinEcho(bool enable)
{
#ifdef WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode;
  GetConsoleMode(hStdin, &mode);
  if (!enable)
  {
    mode &= ~ENABLE_ECHO_INPUT;
  }
  else
  {
    mode |= ENABLE_ECHO_INPUT;
  }
  SetConsoleMode(hStdin, mode);
#else
  struct termios tty;
  tcgetattr(STDIN_FILENO, &tty);
  if (!enable)
  {
    tty.c_lflag &= ~ECHO;
  }
  else
  {
    tty.c_lflag |= ECHO;
  }
  (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

int main(int argc, const char *argv[])
{
  if (argc < 2)
  {
    std::cerr << "Usage: pwned-cli <md5_count_file>" << std::endl;
    return EXIT_FAILURE;
  }
  pwned::PasswordInspector inspector(argv[1]);
  for (;;)
  {
    std::cout << "Password? ";
    std::string pwd;
    setStdinEcho(false);
    std::cin >> pwd;
    setStdinEcho(true);
    const pwned::Hash soughtHash(pwd);
    std::cout << "MD5 hash " << soughtHash << std::endl;
    const auto &t0 = std::chrono::high_resolution_clock::now();
    pwned::PasswordHashAndCount phc = inspector.smart_binsearch(soughtHash);
    const auto &t1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0);
    if (phc.count > 0)
    {
      std::cout << "Found " << std::dec << phc.count << " times." << std::endl;
    }
    else
    {
      std::cout << "Not found." << std::endl;
    }
    std::cout << "Lookup time: " << time_span.count() * 1000 << " ms" << std::endl
              << std::endl;
  }
  return EXIT_SUCCESS;
}
