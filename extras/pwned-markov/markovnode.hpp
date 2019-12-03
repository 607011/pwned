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
#include <algorithm>
#include <numeric>
#include <cstdint>

namespace markov {

class Node
{
public:
  Node() = default;
  void update()
  {
    using count_type = decltype(mCounts)::value_type;
    const std::size_t sum = std::accumulate(std::begin(mCounts), std::end(mCounts), 0ULL,
      [](std::size_t a, const count_type &b) {
        return b.second + a;
      });
    for (const auto &p : mCounts)
    {
      mProbs[p.first] = (double)p.second / (double)sum;
    }
    using prob_type = decltype(mProbs)::value_type;
    auto maxElement = std::max_element(std::begin(mProbs), std::end(mProbs),
      [](const prob_type &a, const prob_type &b) {
        return a.second < b.second;
      });
    mMaxProbElement = *maxElement;
  }
  double probability(wchar_t c) const
  {
    return mProbs.at(c);
  }
  std::size_t count(wchar_t c) const
  {
    return mCounts.at(c);
  }
  void increment(wchar_t c)
  {
    ++mCounts[c];
  }
  const std::unordered_map<wchar_t, double> &successors() const
  {
    return mProbs;
  }
  std::size_t size() const
  {
    return mCounts.size();
  }
  const std::pair<wchar_t, double> &maxProbElement() const
  {
    return mMaxProbElement;
  }

private:
  std::unordered_map<wchar_t, double> mProbs;
  std::unordered_map<wchar_t, std::size_t> mCounts;
  std::pair<wchar_t, double> mMaxProbElement;
};

}

#endif // __markovnode_hpp__
