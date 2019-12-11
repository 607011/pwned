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

namespace pwned
{

namespace markov
{

void Node::update()
{
  using count_type = decltype(mCounts)::value_type;
  const uint64_t sum = std::accumulate(std::begin(mCounts), std::end(mCounts), 0ULL,
                                       [](uint64_t a, const count_type &b) {
                                         return b.second + a;
                                       });
  for (const auto &p : mCounts)
  {
    mProbs[p.first] = (double)p.second / (double)sum;
  }
  mSortedProbs.clear();
  mSortedProbs.reserve(mProbs.size());
  std::copy(std::begin(mProbs), std::end(mProbs), std::begin(mSortedProbs));
  struct {
    bool operator()(const Node::prob_type &a, const Node::prob_type &b) const
    {
      return a.second < b.second;
    }
  } probLess;
  std::sort(std::begin(mSortedProbs), std::end(mSortedProbs), probLess);
}

void Node::clear()
{
  mProbs.clear();
  mSortedProbs.clear();
}

Node::prob_value_type Node::probability(wchar_t c) const
{
  return mProbs.at(c);
}

uint64_t Node::count(wchar_t c) const
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
  return mSortedProbs.front();
}

const Node::prob_type &Node::maxProbElement() const
{
  return mSortedProbs.back();
}

} // namespace markov

} // namespace pwned
