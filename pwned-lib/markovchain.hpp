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

#ifndef __markovchain_hpp__
#define __markovchain_hpp__

#include <unordered_map>
#include <vector>
#include <string>
#include <cstdint>
#include <iostream>

#include "markovnode.hpp"

namespace pwned {

namespace markov {

class Chain
{
public:
  using map_type = std::unordered_map<wchar_t, Node>;
  using prob_type = std::pair<wchar_t, double>;
  using prob_value_type = prob_type::second_type;

  Chain() = default;
  void update();
  void clear();
  void addPair(wchar_t current, wchar_t successor);
  void addFirst(wchar_t letter);
  const map_type &nodes() const;
  void writeJson(std::ostream &os);
  bool readJson(std::istream &is, bool doClear = true);
  void writeBinary(std::ostream &os);
  bool readBinary(std::istream &is, bool doClear = true);
  const std::vector<prob_type>& firstLetterProbs() const;

private:
  map_type mNodes;
  std::unordered_map<wchar_t, uint64_t> mFirstLetterCounts;
  std::unordered_map<wchar_t, prob_value_type> mFirstLetterProbs;
  std::vector<prob_type> mFirstLetterSortedProbs;
  static const char FileHeader[4];
};

} // namespace markov

} // namespace pwned

#endif // __markovnode_hpp__
