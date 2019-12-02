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
#include <string>
#include <cstdint>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/locale/encoding_utf.hpp>

#include "markovnode.hpp"

namespace markov {

namespace pt = boost::property_tree;

class Chain
{
public:
  using map_type = std::unordered_map<wchar_t, Node>;
  Chain() = default;
  void update()
  {
    for (auto &node : mNodes)
    {
      node.second.update();
    }
  }
  void addPair(wchar_t current, wchar_t successor)
  {
    if (mNodes.find(current) == mNodes.end())
    {
      mNodes[current] = Node();
    }
    mNodes[current].increment(successor);
  }
  const map_type &nodes() const
  {
    return mNodes;
  }
  void writeJson(std::ostream &os)
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
  void writeBinary(std::ostream &os)
  {
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

private:
  map_type mNodes;
};

}
#endif // __markovnode_hpp__
