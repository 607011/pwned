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
#include <cstring>
#include <iostream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/locale/encoding_utf.hpp>

#include "markovnode.hpp"

namespace pwned {

namespace markov {

namespace pt = boost::property_tree;

template <typename T>
static inline T read(std::istream &is)
{
  T data;
  is.read(reinterpret_cast<char*>(&data), sizeof(data));
  return data;
}

template <typename T>
static inline void write(std::ostream &os, T data)
{
  os.write(reinterpret_cast<const char*>(&data), sizeof(data));
}  

template <
  typename SymbolType = wchar_t,
  typename ProbabilityType = double,
  typename CountType = uint64_t
  >
class Chain
{
public:
  using symbol_type = SymbolType;
  using prob_value_type = ProbabilityType;
  using count_type = CountType;
  using node_type = Node<symbol_type, prob_value_type>;
  using map_type = std::unordered_map<symbol_type, node_type>;
  using pair_type = std::pair<symbol_type, prob_value_type>;

  Chain() = default;
  void update()
  {
    using elem_type = typename decltype(mFirstSymbolCounts)::value_type;
    const count_type sum = std::accumulate(std::cbegin(mFirstSymbolCounts), std::cend(mFirstSymbolCounts), 0U,
                                           [](count_type a, const elem_type &b) -> count_type {
                                             return b.second + a;
                                           });
    for (const auto &p : mFirstSymbolCounts)
    {
      mFirstSymbolProbs[p.first] = (prob_value_type)p.second / (prob_value_type)sum;
    }
    mFirstSymbolSortedProbs.resize(mFirstSymbolProbs.size());
    std::copy(std::cbegin(mFirstSymbolProbs), std::cend(mFirstSymbolProbs), std::begin(mFirstSymbolSortedProbs));
    using prob_type = std::pair<Chain::symbol_type, prob_value_type>;
    struct {
      bool operator()(const prob_type &a, const prob_type &b) const
      {
        return a.second < b.second;
      }
    } probLess;
    std::sort(std::begin(mFirstSymbolSortedProbs), std::end(mFirstSymbolSortedProbs), probLess);
    for (auto &node : mNodes)
    {
      node.second.update();
    }
  }
  void clear()
  {
    mFirstSymbolProbs.clear();
    mFirstSymbolSortedProbs.clear();
  }
  bool train(const std::string &pwd)
  {
    if (pwd.empty())
      return false;
    const std::basic_string<symbol_type> &s32 = boost::locale::conv::utf_to_utf<symbol_type>(pwd.c_str(), pwd.c_str() + pwd.size());
    if (!s32.empty()) {
      addFirst(s32.at(0));
      if (s32.size() > 1)
      {
        for (size_t i = 0; i < s32.size() - 1; ++i)
        {
          addPair(s32.at(i), s32.at(i+1));
        }
      }
      return true;
    }
    return false;
  }
  inline void addFirst(symbol_type symbol)
  {
    if (mFirstSymbolCounts.find(symbol) == mFirstSymbolCounts.end())
    {
      mFirstSymbolCounts.emplace(symbol, 0);
    }
    ++mFirstSymbolCounts[symbol];
  }
  inline void addPair(symbol_type current, symbol_type successor)
  {
    if (mNodes.find(current) == mNodes.end())
    {
      mNodes.emplace(current, node_type());
    }
    mNodes[current].increment(successor);
  }
  inline const map_type &nodes() const
  {
    return mNodes;
  }
  prob_value_type totalProbability(const std::basic_string<symbol_type> &pwd)
  {
    if (pwd.empty())
      return -1;
    const symbol_type s = pwd.at(0);
    const auto &firstSymbol = std::find_if(
        mFirstSymbolSortedProbs.cbegin(), mFirstSymbolSortedProbs.cend(),
        [s](const pair_type &p) {
          return p.first == s;
        });
    if (firstSymbol == mFirstSymbolSortedProbs.cend())
      return 0;
    typename map_type::iterator node = mNodes.find(firstSymbol->first);
    prob_value_type p = firstSymbol->second;
    for (auto c = std::next(std::begin(pwd)); c != std::end(pwd); ++c)
    {
      if (node != mNodes.end())
      {
        p *= node->second.probability(*c);
        node = mNodes.find(*c);
      }
      else
      {
        return 0;
      }
    }
    return p;
  }
  void writeBinary(std::ostream &os)
  {
    if (mNodes.empty())
      return;
    os.write(FileHeader, FileHeaderSize);
    write(os, FileVersion);
    write(os, (uint32_t)mFirstSymbolSortedProbs.size());
    for (const auto &prob : mFirstSymbolSortedProbs)
    {
      write(os, prob.first);
      write(os, prob.second);
    }
    write(os, (uint32_t)mNodes.size());
    for (const auto &node : mNodes)
    {
      write(os, node.first);
      write(os, (uint32_t)node.second.sortedSuccessors().size());
      for (const auto &successor : node.second.sortedSuccessors())
      {
        write(os, successor.first);
        write(os, successor.second);
      }
    }
  }
  enum ErrCode {
    OK = 0,
    BAD_HEADER,
    BAD_HEADER_PREMATURE_EOF,
    BAD_VERSION,
    BAD_VERSION_PREMATURE_EOF,
    BAD_SYMBOL_COUNT,
    BAD_SYMBOL_COUNT_PREMATURE_EOF,
    BAD_SYMBOL,
    BAD_SYMBOL_PREMATURE_EOF,
    BAD_PROBABILITY,
    BAD_PROBABILITY_PREMATURE_EOF,
    BAD_NODE_COUNT,
    BAD_NODE_COUNT_PREMATURE_EOF
  };
  const std::string &errString(const ErrCode ec) const
  {
    return mErrStrings.at(ec);
  }
  ErrCode readBinary(std::istream &is, bool doClear = true)
  {
    if (doClear)
    {
      mNodes.clear();
      mFirstSymbolCounts.clear();
      mFirstSymbolProbs.clear();
      mFirstSymbolSortedProbs.clear();
    }
    if (is.good() && !is.eof())
    {
      char hdr[FileHeaderSize] = {0, 0, 0, 0};
      is.read(reinterpret_cast<char*>(hdr), FileHeaderSize);
      if (is.eof())
        return BAD_HEADER_PREMATURE_EOF;
      if (memcmp(hdr, FileHeader, FileHeaderSize) != 0)
        return BAD_HEADER;
      uint8_t version = read<uint8_t>(is);
      if (is.eof())
        return BAD_VERSION_PREMATURE_EOF;
      if (version != FileVersion)
        return BAD_VERSION;
      const uint32_t firstSymbolCount = read<uint32_t>(is);
      if (is.eof())
        return BAD_SYMBOL_COUNT_PREMATURE_EOF;
      mFirstSymbolSortedProbs.reserve(firstSymbolCount);
      for (uint32_t i = 0; i < firstSymbolCount; ++i)
      {
        const symbol_type c = read<symbol_type>(is);
        if (is.eof())
          return BAD_SYMBOL_PREMATURE_EOF;
        const prob_value_type p = read<prob_value_type>(is);
        if (is.eof())
          return BAD_PROBABILITY_PREMATURE_EOF;
        mFirstSymbolSortedProbs.emplace_back(c, p);
      }
      const uint32_t symbolCount = read<uint32_t>(is);
      if (is.eof())
        return BAD_SYMBOL_COUNT_PREMATURE_EOF;
      for (uint32_t i = 0; i < symbolCount; ++i)
      {
        symbol_type c = read<symbol_type>(is);
        if (is.eof())
          return BAD_SYMBOL_PREMATURE_EOF;
        if (mNodes.find(c) == mNodes.end())
        {
          mNodes.emplace(c, node_type());
        }
        else
        {
          return BAD_SYMBOL;
        }
        const uint32_t nodeCount = read<uint32_t>(is);
        if (is.eof())
          return BAD_NODE_COUNT_PREMATURE_EOF;
        node_type &currentNode = mNodes[c];
        for (uint32_t j = 0; j < nodeCount; ++j)
        {
          const symbol_type symbol = read<symbol_type>(is);
          if (is.eof())
            return BAD_SYMBOL_PREMATURE_EOF;
          const prob_value_type probability = read<prob_value_type>(is);
          if (is.eof())
            return BAD_PROBABILITY_PREMATURE_EOF;
          currentNode.addSuccessor(symbol, probability);
        }
      }
    }
    for (auto &node : mNodes)
    {
      node.second.postprocess();
    }
    return OK;
  }
  void writeJson(std::ostream &os)
  {
    pt::ptree first;
    for (const auto &firstSymbol : mFirstSymbolSortedProbs)
    {
      first.put<double>(std::to_string(firstSymbol.first), firstSymbol.second);
    }
    pt::ptree successor;
    for (const auto &node : mNodes)
    {
      pt::ptree child;
      for (const auto &successor : node.second.sortedSuccessors())
      {
        child.put<double>(std::to_string(successor.first), successor.second);
      }
      successor.put_child(std::to_string(node.first), child);
    }
    pt::ptree root;
    root.put_child("first", first);
    root.put_child("successor", successor);
    pt::write_json(os, root, true);
  }
  inline const std::vector<pair_type>& firstSymbolProbs() const
  {
    return mFirstSymbolSortedProbs;
  }
  symbol_type randomFirstSymbol() const
  {
    const prob_value_type p = pwned::random();
    prob_value_type pAccumulated = 0.0;
    for (const auto &symbol : mFirstSymbolSortedProbs)
    {
      pAccumulated += symbol.second;
      if (p > pAccumulated)
        return symbol.first;
    }
    return 0;
  }

private:
  map_type mNodes;
  std::unordered_map<symbol_type, count_type> mFirstSymbolCounts;
  std::unordered_map<symbol_type, prob_value_type> mFirstSymbolProbs;
  std::vector<pair_type> mFirstSymbolSortedProbs;
  static const size_t FileHeaderSize{4};
  const char FileHeader[FileHeaderSize]{'M', 'R', 'K', 'V'};
  static const uint8_t FileVersion = 2;
  const std::vector<std::string> mErrStrings{
    "OK",
    "BAD_HEADER",
    "BAD_HEADER_PREMATURE_EOF",
    "BAD_VERSION",
    "BAD_VERSION_PREMATURE_EOF",
    "BAD_SYMBOL_COUNT",
    "BAD_SYMBOL_COUNT_PREMATURE_EOF",
    "BAD_SYMBOL",
    "BAD_SYMBOL_PREMATURE_EOF",
    "BAD_PROBABILITY",
    "BAD_PROBABILITY_PREMATURE_EOF",
    "BAD_NODE_COUNT"
    "BAD_NODE_COUNT_PREMATURE_EOF"
  };
};

} // namespace markov

} // namespace pwned

#endif // __markovnode_hpp__
