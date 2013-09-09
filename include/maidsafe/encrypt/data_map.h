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

#ifndef MAIDSAFE_ENCRYPT_DATA_MAP_H_
#define MAIDSAFE_ENCRYPT_DATA_MAP_H_

#include <cstdint>
#include <string>
#include <vector>
#include <tuple>

#include "maidsafe/common/crypto.h"
#include "boost/shared_array.hpp"


namespace maidsafe {

namespace encrypt {

struct ChunkDetails {
  enum PreHashState { kEmpty, kOutdated, kOk };
  enum StorageState { kStored, kPending, kUnstored };
  ChunkDetails() : hash(),
                   pre_hash(),
                   old_n1_pre_hash(),
                   old_n2_pre_hash(),
                   pre_hash_state(kEmpty),
                   storage_state(kUnstored),
                   size(0) {}
  friend
  bool operator==(const ChunkDetails& lhs, const ChunkDetails& rhs)  {
    return std::tie(lhs.hash,
                    lhs.pre_hash,
                    lhs.old_n1_pre_hash,
                    lhs.old_n2_pre_hash,
                    lhs.pre_hash_state,
                    lhs.storage_state,
                    lhs.size) ==
        std::tie(rhs.hash,
                 rhs.pre_hash,
                 rhs.old_n1_pre_hash,
                 rhs.old_n2_pre_hash,
                 rhs.pre_hash_state,
                 rhs.storage_state,
                 rhs.size);
  }

  friend
  bool operator!=(const ChunkDetails& lhs, const ChunkDetails& rhs)  {
    return !operator==(lhs, rhs);
  }

  std::string hash;  // SHA512 of processed chunk
  byte pre_hash[crypto::SHA512::DIGESTSIZE];  // SHA512 of unprocessed src data
  // pre hashes of chunks n-1 and n-2, only valid if chunk n-1 or n-2 has
  // modified content
  std::vector<byte> old_n1_pre_hash, old_n2_pre_hash;
  // If the pre_hash hasn't been calculated, or if data has been written to the
  // chunk since the pre_hash was last calculated, pre_hash_ok should be false.
  PreHashState pre_hash_state;
  StorageState storage_state;
  uint32_t size;  // Size of unprocessed source data in bytes
};

struct DataMap {
  DataMap() : chunks(), content() {}

  friend
  bool operator==(const DataMap& lhs, const DataMap& rhs)  {
    return std::tie(lhs.chunks, lhs.content) == std::tie(rhs.chunks, rhs.content);
  }

  friend
  bool operator!=(const DataMap& lhs, const DataMap& rhs)  {
    return !operator==(lhs, rhs);
  }

  std::vector<ChunkDetails> chunks;
  std::string content;  // Whole data item, if small enough
};

typedef std::shared_ptr<DataMap> DataMapPtr;

std::string SerialiseDataMap(const DataMap& data_map);
DataMap ParseDataMap(const std::string& serialised_data_map);

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
