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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/locale/encoding_utf.hpp>

#include "markovchain.hpp"

namespace markov {

namespace pt = boost::property_tree;

const char Chain::FileHeader[4] = {'M', 'R', 'K', 'V'};

using map_type = Chain::map_type;

void Chain::update()
{
  for (auto &node : mNodes)
  {
    node.second.update();
  }
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

void Chain::writeBinary(std::ostream &os)
{
  os.write(reinterpret_cast<const char*>(&FileHeader), sizeof(FileHeader));
  const uint32_t cnt = (uint32_t)mNodes.size();
  os.write(reinterpret_cast<const char*>(&cnt), sizeof(cnt));
  for (const auto &node : mNodes)
  {
    os.write(reinterpret_cast<const char*>(&node.first), sizeof(node.first));
    const uint32_t cnt = (uint32_t)node.second.successors().size();
    os.write(reinterpret_cast<const char*>(&cnt), sizeof(cnt));
    for (const auto &successor : node.second.successors())
    {
      os.write(reinterpret_cast<const char*>(&successor.first), sizeof(successor.first));
      os.write(reinterpret_cast<const char*>(&successor.second), sizeof(successor.second));
    }
  }
}

bool Chain::readBinary(std::istream &is, bool doClear)
{
  if (doClear)
  {
    mNodes.clear();
  }
  while (!is.eof())
  {
    char hdr[4];
    is.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (is.eof())
      return false;
    if (memcmp(hdr, FileHeader, 4) != 0)
      return false;
    uint32_t symbolCount;
    is.read(reinterpret_cast<char*>(&symbolCount), sizeof(symbolCount));
    if (is.eof())
      return false;
    for (auto i = 0; i < symbolCount; ++i)
    {
      wchar_t c;
      is.read(reinterpret_cast<char*>(&c), sizeof(c));
      if (is.eof())
        return false;
      if (mNodes.find(c) == mNodes.end())
      {
        mNodes.emplace(std::make_pair(c, Node()));
      }
      if (is.eof())
        return false;
      uint32_t nodeCount;
      is.read(reinterpret_cast<char*>(&nodeCount), sizeof(nodeCount));
      if (is.eof())
        return false;
      Node &currentNode = mNodes[c];
      for (auto j = 0; j < nodeCount; ++j)
      {
        wchar_t symbol;
        double probability;
        is.read(reinterpret_cast<char*>(&symbol), sizeof(symbol));
        if (is.eof())
          return false;
        is.read(reinterpret_cast<char*>(&probability), sizeof(probability));
        if (is.eof())
          return false;
        currentNode.addSuccessor(symbol, probability);
      }
    }
  }
  return true;
}


} // namespace markov
