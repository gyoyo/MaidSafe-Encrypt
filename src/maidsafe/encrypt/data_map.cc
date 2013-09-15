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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"

#include "maidsafe/encrypt/byte_array.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/data_map.pb.h"

namespace maidsafe {

namespace encrypt {

std::string SerialiseDataMap(const DataMap& data_map) {
  protobuf::DataMap proto_data_map;
  if (!data_map.content.empty()) {
    proto_data_map.set_content(data_map.content);
  } else {
    for (auto& chunk_detail : data_map.chunks) {
      protobuf::ChunkDetails* chunk_details = proto_data_map.add_chunk_details();
      assert(chunk_detail.clean && "cannot serialise a dirty data map");
      chunk_details->set_hash(chunk_detail.hash.string());
      chunk_details->set_pre_hash(chunk_detail.pre_hash.string());
      chunk_details->set_size(chunk_detail.size);
    }
  }
  return proto_data_map.SerializeAsString();
}

void ExtractChunkDetails(const protobuf::DataMap& proto_data_map, DataMap& data_map) {
  data_map.chunks.clear();
  data_map.chunks.reserve(proto_data_map.chunk_details().size());
  for (auto& chunk : proto_data_map.chunk_details())
    data_map.chunks.emplace_back(DataMap::ChunkDetails(PostHash(chunk.hash()),
                                                       PreHash(chunk.pre_hash()),
                                                       chunk.size()));
}

DataMap ParseDataMap(const std::string& serialised_data_map) {
  protobuf::DataMap proto_data_map;
  DataMap data_map;
  proto_data_map.ParseFromString(serialised_data_map);

  if (proto_data_map.has_content() && proto_data_map.chunk_details_size() != 0) {
    data_map.content = proto_data_map.content();
    ExtractChunkDetails(proto_data_map, data_map);
  } else if (proto_data_map.has_content()) {
    data_map.content = proto_data_map.content();
  } else if (proto_data_map.chunk_details_size() != 0) {
    ExtractChunkDetails(proto_data_map, data_map);
  }
  return data_map;
}

}  // namespace encrypt

}  // namespace maidsafe
