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

#include <algorithm>
#include <numeric>

#include "markovnode.hpp"

namespace markov
{

void Node::update()
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

double Node::probability(wchar_t c) const
{
  return mProbs.at(c);
}

std::size_t Node::count(wchar_t c) const
{
  return mCounts.at(c);
}

void Node::increment(wchar_t c)
{
  ++mCounts[c];
}

const std::unordered_map<wchar_t, double> &Node::successors() const
{
  return mProbs;
}

std::size_t Node::size() const
{
  return mCounts.size();
}

const std::pair<wchar_t, double> &Node::maxProbElement() const
{
  return mMaxProbElement;
}

} // namespace pwned
