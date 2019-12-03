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

#include <utility>
#include <algorithm>
#include <numeric>

#include "markovnode.hpp"

namespace markov
{

void Node::update()
{
  using count_type = decltype(mCounts)::value_type;
  const size_t sum = std::accumulate(std::begin(mCounts), std::end(mCounts), 0ULL,
                                     [](size_t a, const count_type &b) {
                                       return b.second + a;
                                     });
  for (const auto &p : mCounts)
  {
    mProbs[p.first] = (double)p.second / (double)sum;
  }
  auto maxElement = std::max_element(std::begin(mProbs), std::end(mProbs),
                                     [](const Node::prob_type &a, const Node::prob_type &b) {
                                       return a.second < b.second;
                                     });
  mMaxProbElement = *maxElement;
  auto minElement = std::min_element(std::begin(mProbs), std::end(mProbs),
                                     [](const Node::prob_type &a, const Node::prob_type &b) {
                                       return a.second < b.second;
                                     });
  mMinProbElement = *minElement;
}

Node::prob_value_type Node::probability(wchar_t c) const
{
  return mProbs.at(c);
}

size_t Node::count(wchar_t c) const
{
  return mCounts.at(c);
}

void Node::increment(wchar_t c)
{
  ++mCounts[c];
}

const Node::prob_map_type &Node::successors() const
{
  return mProbs;
}

void Node::addSuccessor(wchar_t c, double probability)
{
  mProbs[c] = probability;
}

size_t Node::size() const
{
  return mCounts.size();
}

const Node::prob_type &Node::minProbElement() const
{
  return mMinProbElement;
}

const Node::prob_type &Node::maxProbElement() const
{
  return mMaxProbElement;
}

} // namespace pwned
