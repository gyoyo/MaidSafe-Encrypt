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
#include <vector>
#include <tuple>

#include "maidsafe/common/types.h"
#include "maidsafe/encrypt/utils.h"

namespace maidsafe {

namespace encrypt {


typedef TaggedValue<Identity, struct PreHashTag> PreHash;
typedef TaggedValue<Identity, struct PostHashTag> PostHash;


// move only! datamap object

struct DataMap {
  DataMap() : chunks(), content() {}

 DataMap(DataMap&& other)
 : chunks(std::move(other.chunks)),
   content(std::move(other.content)) {}

 ~DataMap() {}

 friend
  bool operator==(const DataMap& lhs, const DataMap& rhs)  {
    return std::tie(lhs.chunks, lhs.content) == std::tie(rhs.chunks, rhs.content);
  }

 friend
  bool operator!=(const DataMap& lhs, const DataMap& rhs)  {
    return !operator==(lhs, rhs);
  }

  struct ChunkDetails {
    ChunkDetails() : post_hash(),
      pre_hash(),
      clean(false),
      size(0) {}

    ChunkDetails(PostHash post_hash, PreHash pre_hash, uint32_t size)
      : post_hash(post_hash),
        pre_hash(pre_hash),
        clean(true),
        size(size) {}

    ChunkDetails(const ChunkDetails& other)
      : post_hash(other.post_hash),
        pre_hash(other.pre_hash),
        clean(other.clean),
        size(other.size){}

   ChunkDetails(ChunkDetails&& other)
    : post_hash(std::move(other.post_hash)),
      pre_hash(std::move(other.pre_hash)),
      clean(std::move(other.clean)),
      size(std::move(other.size)){}

   friend
    bool operator==(const ChunkDetails& lhs, const ChunkDetails& rhs)  {
      return std::tie(lhs.post_hash,
                      lhs.pre_hash,
                      lhs.clean,
                      lhs.size) ==
          std::tie(rhs.post_hash,
                   rhs.pre_hash,
                   rhs.clean,
                   rhs.size);
    }
   friend
    bool operator!=(const ChunkDetails& lhs, const ChunkDetails& rhs)  {
      return !operator==(lhs, rhs);
    }

    PostHash post_hash;  // hash of processed chunk
    PreHash pre_hash;  // hash of unprocessed src data
    bool clean;  // requires to be re-encrypted (new data available)
    uint32_t size;  // Size of unprocessed source data in bytes
  };
  // return vector of data (may be empty) / mark dirty
  std::vector<PostHash> DataAtPosition(int64_t position, int32_t length);
  void MarkDataDownloaded(std::vector<PostHash> chunks);

  std::vector<ChunkDetails> chunks;
  std::string content;  // Whole data item, if small enough
private:
  DataMap(const DataMap&);
  DataMap& operator=(DataMap&);
};

std::string SerialiseDataMap(const DataMap& data_map);
DataMap ParseDataMap(const std::string& serialised_data_map);

// All types to have move ctr / assignment
struct WriteResults {
  DataMap new_data_map;
  DataMap old_data_map;
  data_store::DataBuffer<ImmutableData::Name> ciphertext_data_buffer;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_DATA_MAP_H_
