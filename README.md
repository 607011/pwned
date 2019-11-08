# #pwned tools

_A collection of tools to convert pwned password files to searchable MD5 files, and look up passwords in these files_

![](https://img.shields.io/github/license/ola-ct/pwned.svg)

## Brief description

### Main components

**pwned-lib**: library with basic classes and functions to read and write hashes and their according counts

**pwned-converted-cli**: command-line interface to convert clear-text password files to binary files containing MD5 hashes and their according counts, sorted by hash

**pwned-merger-cli**: command-line interface to merge MD5:count files

**pwned-lookup-cli**: command-line interface to look up passwords in an MD5:count file

**pwned-index**: command-line interface to build an index of an MD5:count file

**pwned-server**: a RESTful web service to look up hashes

**pwned-server/loadttest**: a load tester for the RESTful web service



### Auxiliary programs

**extras/test-set-extractor**: command-line interface to extract a test set from a MD5:count file containing existent and non-existents hashes (used by benchmark)

**extras/benchmark**: command-line interface to run performance tests with different search algorithms

**deprecated/be2le**: command-line interface to convert a binary MD5:count file from Big-Endian to Little-Endian representation (no longer needed because the current release of pwned-converter-cli and pwneder-merger-cli already produces Little-Endian data)

## Prerequisites

### Ubuntu 19.xx / Raspi w/ Debian Buster

Install necessary programs and libraries:

```
sudo apt install git cmake c++ \
  libssl-dev \
  libboost-dev \
  libboost-program-options-dev \
  libboost-date-time-dev
```

The #pwned tools need Boost 1.71 to compile. Follow the instructions on [how to build Boost](https://www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html) on your own.

In brief:

```
mkdir -p ~/dev/boost-1.71
wget https://dl.bintray.com/boostorg/release/1.71.0/source/boost_1_71_0.tar.bz2
tar xjvf boost_1_71_0.tar.bz2
cd boost_1_71_0
./bootstrap.sh --prefix=~/dev/boost-1.71
./b2 install
```

## Get #pwned source code

Check out #pwned tools from GitHub:

```
mkdir -p ~/dev
cd ~/dev
git clone https://github.com/ola-ct/pwned.git
```

## Build for release

Go to the build directory:

```
cd pwned/build/Release
```

Start the build process:

```
cmake -DCMAKE_BUILD_TYPE=Release ../..
make
```

If `cmake` can't find OpenSSL, set the environment variable `OPENSSL_ROOT_DIR` to
an appropriate value, e.g.:

```
export OPENSSL_ROOT_DIR=/usr/local/opt/openssl
```

Then call `cmake` again as shown above.

If you compiled Boost 1.71 on your own as shown above, you have to introduce it to `cmake`:

```
BOOST_ROOT=~/dev/boost-1.71 cmake -DCMAKE_BUILD_TYPE=Release ../..
```

## Literature

 - [Oliver Lau, Cleverer/2, Wie man die binäre Suche pimpen kann, c't 23/2019, S. 172](https://www.heise.de/select/ct/2019/23/1572876495268649)
 - [Pina Merkert, Passwortsuche mit Turbo, 25 Gigabyte Passwortlisten von HaveIBeenPwned schnell lokal durchsuchen, c't 5/2019, S. 42](https://www.heise.de/select/ct/2019/5/1551437903574108)

---

Copyright &copy; 2019 [Oliver Lau](mailto:ola@ct.de), [Heise Medien GmbH & Co. KG](http://www.heise.de/).

Dieses Programm ist freie Software. Sie können es unter den Bedingungen der [GNU General Public License](http://www.gnu.org/licenses/gpl-3.0), wie von der Free Software Foundation veröffentlicht, weitergeben und/oder modifizieren, entweder gemäß Version 3 der Lizenz oder (nach Ihrer Wahl) jeder späteren Version.

__Diese Software wurde zu Lehr- und Demonstrationszwecken programmiert und ist nicht für den produktiven Einsatz vorgesehen. Der Autor und die Heise Medien GmbH & Co. KG haften nicht für eventuelle Schäden, die aus der Nutzung der Software entstehen, und übernehmen keine Gewähr für ihre Vollständigkeit, Fehlerfreiheit und Eignung für einen bestimmten Zweck.__

---

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
