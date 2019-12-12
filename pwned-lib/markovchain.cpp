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

#include <iostream>
#include <numeric>
#include <algorithm>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "markovchain.hpp"

namespace pwned {

namespace markov {

namespace pt = boost::property_tree;

const char Chain::FileHeader[4] = {'M', 'R', 'K', 'V'};

using map_type = Chain::map_type;

void Chain::update()
{
  using count_type = decltype(mFirstLetterCounts)::value_type;
  const uint64_t sum = std::accumulate(std::cbegin(mFirstLetterCounts), std::cend(mFirstLetterCounts), 0ULL,
                                       [](uint64_t a, const count_type &b) {
                                         return b.second + a;
                                       });
  for (const auto &p : mFirstLetterCounts)
  {
    mFirstLetterProbs[p.first] = (double)p.second / (double)sum;
  }
  mFirstLetterSortedProbs.clear();
  mFirstLetterSortedProbs.reserve(mFirstLetterProbs.size());
  std::copy(std::begin(mFirstLetterProbs), std::end(mFirstLetterProbs), std::begin(mFirstLetterSortedProbs));
  using prob_type = std::pair<wchar_t, double>;
  struct {
    bool operator()(const prob_type &a, const prob_type &b) const
    {
      return a.second < b.second;
    }
  } probLess;
  std::sort(std::begin(mFirstLetterSortedProbs), std::end(mFirstLetterSortedProbs), probLess);
  for (auto &node : mNodes)
  {
    node.second.update();
  }
}

void Chain::clear()
{
  mFirstLetterProbs.clear();
  mFirstLetterSortedProbs.clear();
}

void Chain::addFirst(wchar_t letter)
{
  if (mFirstLetterCounts.find(letter) == mFirstLetterCounts.end())
  {
    mFirstLetterCounts.emplace(std::make_pair(letter, 0));
  }
  ++mFirstLetterCounts[letter];
}

void Chain::addPair(wchar_t current, wchar_t successor)
{
  if (mNodes.find(current) == mNodes.end())
  {
    mNodes.emplace(std::make_pair(current, Node()));
  }
  mNodes[current].increment(successor);
}

const map_type &Chain::nodes() const
{
  return mNodes;
}

void Chain::writeJson(std::ostream &os)
{
  pt::ptree root;
  for (const auto &node : mNodes)
  {
    pt::ptree child;
    for (const auto &successor : node.second.successors())
    {
      child.put<double>(std::to_string(successor.first), successor.second);
    }
    root.put_child(std::to_string(node.first), child);
  }
  pt::write_json(os, root, true);
}

bool Chain::readJson(std::istream &is, bool doClear)
{
  if (doClear)
  {
    mNodes.clear();
  }
  pt::ptree root;
  pt::read_json(is, root);
  // TODO

  return true;
}

template <typename T>
inline T read(std::istream &is)
{
  T data;
  is.read(reinterpret_cast<char*>(&data), sizeof(data));
  return data;
}

template <typename T>
inline void write(std::ostream &os, T data)
{
  os.write(reinterpret_cast<const char*>(&data), sizeof(data));
}

void Chain::writeBinary(std::ostream &os)
{
  if (mNodes.empty())
    return;
  os.write(FileHeader, 4);
  write(os, (uint32_t)mFirstLetterSortedProbs.size());
  for (const auto &prob : mFirstLetterSortedProbs)
  {
    write(os, prob.first);
    write(os, prob.second);
  }
  write(os, (uint32_t)mNodes.size());
  for (const auto &node : mNodes)
  {
    write(os, node.first);
    write(os, (uint32_t)node.second.successors().size());
    for (const auto &successor : node.second.successors())
    {
      write(os, successor.first);
      write(os, successor.second);
    }
  }
}

bool Chain::readBinary(std::istream &is, bool doClear)
{
  if (doClear)
  {
    mNodes.clear();
    mFirstLetterCounts.clear();
    mFirstLetterProbs.clear();
    mFirstLetterSortedProbs.clear();
  }
  while (!is.eof())
  {
    char hdr[4] = {0, 0, 0, 0};
    is.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (is.eof())
      return false;
    if (memcmp(hdr, FileHeader, sizeof(FileHeader)) != 0)
      return false;
    const uint32_t firstSymbolCount = read<uint32_t>(is);
    if (is.eof())
      return false;
    mFirstLetterSortedProbs.reserve(firstSymbolCount);
    for (auto i = 0; i < firstSymbolCount; ++i)
    {
      const wchar_t c = read<wchar_t>(is);
      if (is.eof())
        return false;
      const double p = read<double>(is);
      if (is.eof())
        return false;
      mFirstLetterSortedProbs.emplace_back(c, p);
    }
    const uint32_t symbolCount = read<uint32_t>(is);
    if (is.eof())
      return false;
    for (auto i = 0; i < symbolCount; ++i)
    {
      wchar_t c = read<wchar_t>(is);
      if (is.eof())
        return false;
      if (mNodes.find(c) == mNodes.end())
      {
        mNodes.emplace(c, Node());
      }
      if (is.eof())
        return false;
      const uint32_t nodeCount = read<uint32_t>(is);
      if (is.eof())
        return false;
      Node &currentNode = mNodes[c];
      for (auto j = 0; j < nodeCount; ++j)
      {
        const wchar_t symbol = read<wchar_t>(is);
        if (is.eof())
          return false;
        const double probability = read<double>(is);
        if (is.eof())
          return false;
        currentNode.addSuccessor(symbol, probability);
      }
    }
  }
  return true;
}

const std::vector<Chain::prob_type>& Chain::firstLetterProbs() const
{
  return mFirstLetterSortedProbs;
}

} // namespace markov

} // namespace pwned
