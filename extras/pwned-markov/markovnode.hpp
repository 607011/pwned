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
  using prob_map_type = std::unordered_map<wchar_t, double>;

private:
  prob_map_type mProbs;
  std::unordered_map<wchar_t, size_t> mCounts;
  using prob_type = std::pair<wchar_t, double>;
  prob_type mMinProbElement;
  prob_type mMaxProbElement;
  using prob_value_type = prob_type::second_type;

public:
  Node() = default;
  void update();
  prob_value_type probability(wchar_t c) const;
  size_t count(wchar_t c) const;
  void increment(wchar_t c);
  const prob_map_type &successors() const;
  void addSuccessor(wchar_t, prob_value_type);
  size_t size() const;
  const prob_type &minProbElement() const;
  const prob_type &maxProbElement() const;
};

}

#endif // __markovnode_hpp__
