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
#include <vector>
#include <utility>
#include <algorithm>
#include <numeric>
#include <iterator>
#include <cstdint>

#include "util.hpp"

namespace pwned {

namespace markov {

template <
  typename SymbolType = wchar_t,
  typename ProbabilityType = double,
  typename CountType = uint64_t
  >
class Node
{
public:
  using symbol_type = SymbolType;
  using prob_value_type = ProbabilityType;
  using count_type = CountType;
  using prob_map_type = std::unordered_map<symbol_type, prob_value_type>;
  using pair_type = std::pair<symbol_type, prob_value_type>;

private:
  prob_map_type mProbs;
  std::unordered_map<symbol_type, count_type> mCounts;
  std::vector<pair_type> mSortedProbs;

public:
  Node() = default;
  void update()
  {
    using elem_type = typename decltype(mCounts)::value_type;
    const count_type sum = std::accumulate(std::cbegin(mCounts), std::cend(mCounts), 0ULL,
                                           [](count_type a, const elem_type &b) {
                                             return b.second + a;
                                           });
    for (const auto &p : mCounts)
    {
      mProbs[p.first] = (Node::prob_value_type)p.second / (Node::prob_value_type)sum;
    }
    mSortedProbs.clear();
    mSortedProbs.reserve(mProbs.size());
    std::copy(std::cbegin(mProbs), std::cend(mProbs), std::begin(mSortedProbs));
    struct {
      bool operator()(const Node::pair_type &a, const Node::pair_type &b) const
      {
        return a.second < b.second;
      }
    } probLess;
    std::sort(std::begin(mSortedProbs), std::end(mSortedProbs), probLess);
  }
  void clear()
  {
    mProbs.clear();
    mSortedProbs.clear();
  }
  inline prob_value_type probability(symbol_type c) const
  {
    return mProbs.at(c);
  }
  inline uint64_t count(symbol_type c) const
  {
    return mCounts.at(c);
  }
  inline void increment(symbol_type c)
  {
    ++mCounts[c];
  }
  inline const prob_map_type &successors() const
  {
    return mProbs;
  }
  inline const std::vector<pair_type> &sortedSuccessors() const
  {
    return mSortedProbs;
  }
  inline void addSuccessor(symbol_type c, prob_value_type probability)
  {
    mProbs[c] = probability;
  }
  inline size_t size() const
  {
    return mCounts.size();
  }
  symbol_type randomSuccessor() const
  {
    const typename Node<SymbolType, ProbabilityType>::prob_value_type p = pwned::random();
    Node::prob_value_type pAccumulated = 0.0;
    for (const auto &successor : mSortedProbs)
    {
      pAccumulated += successor.second;
      if (p > pAccumulated)
        return successor.first;
    }
    return 0;
  }
};

} // namespace markov

} // namespace pwned

#endif // __markovnode_hpp__
