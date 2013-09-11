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

#ifndef MAIDSAFE_ENCRYPT_SEQUENCER_H_
#define MAIDSAFE_ENCRYPT_SEQUENCER_H_

#include <cstdint>
#include <limits>
#include <map>

#include "maidsafe/encrypt/utils.h"

namespace maidsafe {
namespace encrypt {

class Sequencer {
 public:
  Sequencer() : blocks_() {}
  // Adds a new block to the map.  If this overlaps or joins any existing ones,
  // the new block is set to cover the total span of all the overlapping blocks
  // and the old ones are removed.
  void Write(const char* data, const uint32_t &length, int64_t position);
  std::map<uint64_t, Chars>::iterator Find(int32_t position);
  // Returns and removes the block of sequenced data at position in the map.
  char* Fetch(int64_t position);
  // Returns a copy block of sequenced data at position in the map.
  char* Read(int64_t position);
  // Removes all blocks after position, and reduces any block spanning position
  // to terminate at position.
  void Truncate(int64_t position);
  void clear() { blocks_.clear(); }
  size_t size();

 private:
  Sequencer &operator=(const Sequencer&);
  Sequencer(const Sequencer&);
  std::map<uint64_t, Chars> blocks_;
};

}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SEQUENCER_H_
