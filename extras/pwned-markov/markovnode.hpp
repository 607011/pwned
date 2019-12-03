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

#ifndef __markovnode_hpp__
#define __markovnode_hpp__

#include <unordered_map>
#include <cstdint>

namespace markov {

class Node
{
public:
  Node() = default;
  void update();
  double probability(wchar_t c) const;
  std::size_t count(wchar_t c) const;
  void increment(wchar_t c);
  const std::unordered_map<wchar_t, double> &successors() const;
  std::size_t size() const;
  const std::pair<wchar_t, double> &maxProbElement() const;

private:
  std::unordered_map<wchar_t, double> mProbs;
  std::unordered_map<wchar_t, std::size_t> mCounts;
  std::pair<wchar_t, double> mMaxProbElement;
};

}

#endif // __markovnode_hpp__
