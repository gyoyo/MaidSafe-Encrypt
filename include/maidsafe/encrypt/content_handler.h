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
      self_encryptor_(sequencer_) {}

  explicit ContentHandler(DataMap data_map)
    : data_map_(data_map),
      get_data_functor_() {}

  ContentHandler()
    : data_map_(),
      get_data_functor_() {}

  ContentHandler(const ContentHandler& other)
    : data_map_(other.data_map_),
      get_data_functor_(other.get_data_functor_) {}

  ContentHandler(ContentHandler&& other)
    : data_map_(std::move(other.data_map_)),
      get_data_functor_(std::move(other.get_data_functor_)) {}

  ~ContentHandler() {}

  ContentHandler& operator=(ContentHandler other) {
    swap(*this, other);
    return *this;
  }

  friend
  bool operator==(const ContentHandler& lhs, const ContentHandler& rhs) {
    return std::tie(lhs.data_map_, lhs.get_data_functor_)
        == std::tie(rhs.data_map_, rhs.get_data_functor_);
  }

  friend
  bool operator!=(const ContentHandler& lhs, const ContentHandler& rhs) {
    return !operator==(lhs, rhs);
  }

  friend
  bool operator<(const ContentHandler& lhs, const ContentHandler& rhs) {
    return std::tie(lhs.data_map_, lhs.get_data_functor_)
        < std::tie(rhs.data_map_, rhs.get_data_functor_);
  }

  friend
  bool operator>(const ContentHandler& lhs, const ContentHandler& rhs) {
    return operator<(rhs, lhs);
  }

  friend
  bool operator<=(const ContentHandler& lhs, const ContentHandler& rhs) {
    return !operator>(lhs, rhs);
  }

  friend
  bool operator>=(const ContentHandler& lhs, const ContentHandler& rhs) {
    return !operator<(lhs, rhs);
  }

  void Write(const char* data, const uint32_t &length, int64_t position);
  char* Read(int64_t length, int64_t position);
  void Truncate(int64_t position);
  WriteResults Flush();  // old data map is replaced with new datamap (copy)
  WriteResults Close();  // Move
  int64_t size() const;

private:
  Sequencer sequencer_;
  SelfEncryptor self_encryptor_;
};

// swap
void swap(ContentHandler& lhs, ContentHandler& rhs) /* noexcept */ {
  using std::swap;
  swap(lhs.data_map_, rhs.data_map_);
  swap(lhs.get_data_functor_, rhs.get_data_functor_);
}




}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CONTENT_HANDLER_H_
