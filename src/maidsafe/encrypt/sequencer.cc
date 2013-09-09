/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */
#include "maidsafe/encrypt/sequencer.h"

#include <iterator>
#include <algorithm>

#include "maidsafe/common/log.h"
#include "maidsafe/encrypt/config.h"

namespace maidsafe {
namespace encrypt {

void Sequencer::Add(const Chars& data,
                    const uint64_t &position) {

  auto found = Find(position);

  if(found == std::end(blocks_)) {
     blocks_.insert(std::make_pair(position, data));
     return;
  }
  if(found->second.size() < (position - found->first + data.size()))
    found->second.resize(position - found->first + data.size());
  std::move(std::begin(found->second) + (position - found->first),
            std::end(found->second),
            std::back_inserter(data));
  found->second.erase((std::begin(found->second) + (position - found->first)),
                                 std::end(found->second));
//spanning block !!!
  auto current = found;
  auto next = ++found;
  while (current->first + current->second.size() >= next->first) {
    if (current->first + current->second.size() >= next->first + next->second.size()) {
      ++next;
      continue;
    }
    std::move(std::begin(next->second) +
              (current->first + current->second.size() >= next->first + next->second.size()),
              std::end(next->second),
              std::back_inserter(current));
    blocks_.erase(next);
  }
}

std::map<uint64_t, Chars>::iterator Sequencer::Find(int32_t position) {
  return std::find_if(std::begin(blocks_), std::end(blocks_),
                              [position] (const std::pair<uint64_t, Bytes>& entry)
    {
      return (entry.first + entry.second.size() >= static_cast<size_t>(position));
    });
}

Chars Sequencer::Get(const uint64_t &position) {
  auto found = Find(position);
  Chars chars;
  std::move(std::begin(found->second) + (position - found->first),
            std::end(found->second),
            std::back_inserter(chars));
  found->second.erase((std::begin(found->second) + (position - found->first)),
                                 std::end(found->second));
  return chars;
}


//Chars Sequencer::GetFirst() {
//  if (blocks_.empty())
//    return kInvalidSeqBlock;
//  auto result(*blocks_.begin());
//  blocks_.erase(blocks_.begin());
//  return result;
//}

//SequenceBlock Sequencer::PeekBeyond(const uint64_t &position) const {
//  auto itr(blocks_.lower_bound(position));
//  return itr == blocks_.end() ? kInvalidSeqBlock : *itr;
//}

//SequenceBlock Sequencer::Peek(const uint32_t &length,
//                              const uint64_t &position) const {
//  if (blocks_.empty())
//    return kInvalidSeqBlock;

//  auto itr(blocks_.lower_bound(position));
//  if (itr != blocks_.end() && (*itr).first == position)
//    return *itr;

//  if (itr == blocks_.end() || itr != blocks_.begin())
//    --itr;

//  if ((*itr).first < position) {
//    if ((*itr).first + Size((*itr).second) > position)
//      return *itr;
//    else
//      ++itr;
//  }

//  if (itr == blocks_.end())
//    return kInvalidSeqBlock;

//  return ((*itr).first < length + position) ? *itr : kInvalidSeqBlock;
//}

void Sequencer::Truncate(const uint64_t &position) {
  if (blocks_.empty())
    return;
  auto found = Find(position);
  if (found->first == position) {
    blocks_.erase(found, blocks_.end());
  } else {
    found->second.erase(std::begin(found->second) + position - found->first,
                        std::end(found->second));
    blocks_.erase(++found, blocks_.end());
  }
}

}  // namespace encrypt
}  // namespace maidsafe
