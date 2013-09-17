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

#ifndef MAIDSAFE_ENCRYPT_CONTENT_HANDLER_H_
#define MAIDSAFE_ENCRYPT_CONTENT_HANDLER_H_

#include <tuple>
#include <utility>
#include <functional>

#include "maidsafe/data_types/immutable_data.h"
#include "maidsafe/data_store/data_buffer.h"
#include "maidsafe/encrypt/utils.h"
#include "maidsafe/encrypt/sequencer.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryptor.h"

namespace maidsafe {

namespace encrypt {

class ContentHandler {

 public:
  ContentHandler(DataMap data_map, GetDataFromStore get_data_functor)
    : sequencer_(data_map, get_data_functor),
      self_encryptor_(){}

  explicit ContentHandler(DataMap data_map)
    : data_map_(data_map),
      get_data_functor_() {}

  ContentHandler()
    : data_map_(),
      get_data_functor_(),
      size_() {}

  ContentHandler(const ContentHandler& other)
    : data_map_(other.data_map_),
      get_data_functor_(other.get_data_functor_) {}

  ContentHandler(ContentHandler&& other)
    : data_map_(std::move(other.data_map_)),
      get_data_functor_(std::move(other.get_data_functor_)) {}

  ~ContentHandler() {}

  ContentHandler& operator=(ContentHandler& other) = default;

  friend
  bool operator==(const ContentHandler& lhs, const ContentHandler& rhs) {
    return std::tie(lhs.data_map_, lhs.get_data_functor_)
        == std::tie(rhs.data_map_, rhs.get_data_functor_);
  }

  friend
  bool operator!=(const ContentHandler& lhs, const ContentHandler& rhs) {
    return !operator==(lhs, rhs);
  }

  // if write to existing position in data map and it's clean then download that chunk
  // plus next 2 chunks
  // decrypt and write to sequencer
  void Write(const char* data, const uint32_t &length, int64_t position) {
    // chunks at this position mark dirty
    // if chunk at position not downloaded / wait
    // apply
    Chars chars(data, length);
    sequencer_.Write(chars, position);
    if (sequencer_.HighestPosition() > size_)
      size_ = sequencer_.HighestPosition();
  }

  // read from sequencer, as with above if chunk is on net get it first
  char* Read(int64_t position, int32_t length) {
    // if chunk at position !downloaded block and download
    // apply

    auto res =  sequencer_.Read(position, length);
    char* a = new char[res.size() + 1];
    memcpy(a, res.c_str(), res.size());
    return a;
  }

  void Truncate(int64_t position) {
    size_ = position;
    sequencer_.Truncate(position);
    size_ = position;
    // remove datamap chunks after this position
    // invalidate all chunks, possibly
  }

  // add private members to handle encryption and update of data map.
  DataMap Flush();  // old data map is replaced with new datamap (copy)
  DataMap Close();  // Move
  int64_t size() const { return size_; }

 private:
  WriteResults doFlush();
  WriteResults doClose();
  Sequencer sequencer_;
  SelfEncryptor self_encryptor_;
  DataMap data_map_;
  GetDataFromStore get_data_functor_;
  int64_t size_;
};





}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CONTENT_HANDLER_H_
