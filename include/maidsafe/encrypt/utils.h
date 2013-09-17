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

#ifndef MAIDSAFE_ENCRYPT_UTILS_H_
#define MAIDSAFE_ENCRYPT_UTILS_H_

#include <cstdint>
#include <string>
#include <vector>
//#ifdef __MSVC__
//#  pragma warning(push, 1)
//#endif
//#include "cryptopp/aes.h"
//#include "cryptopp/gzip.h"
//#include "cryptopp/modes.h"
//#include "cryptopp/mqueue.h"
//#include "cryptopp/sha.h"
//#ifdef __MSVC__
//#  pragma warning(pop)
//#endif

#include "maidsafe/common/crypto.h"
#include "maidsafe/data_types/immutable_data.h"
#include "maidsafe/data_store/data_buffer.h"
#include "boost/shared_array.hpp"

class DataMap;

namespace maidsafe {

namespace encrypt {
const size_t kPadSize((3 * crypto::SHA512::DIGESTSIZE) -
                      crypto::AES256_KeySize - crypto::AES256_IVSize);

class XORFilter : public CryptoPP::Bufferless<CryptoPP::Filter> {
 public:
  XORFilter(CryptoPP::BufferedTransformation *attachment,
            byte *pad,
            const size_t &pad_size = kPadSize)
      : pad_(pad), count_(0), kPadSize_(pad_size) {
    CryptoPP::Filter::Detach(attachment);
  }
  size_t Put2(const byte* in_string, size_t length, int message_end, bool blocking) {
    if (length == 0) {
      return AttachedTransformation()->Put2(in_string, length, message_end, blocking);
    }
    std::unique_ptr<byte[]> buffer(new byte[length]);

    size_t i(0);
#ifdef MAIDSAFE_OMP_ENABLED
// #  pragma omp parallel for shared(buffer, in_string) private(i)
#endif
    for (; i != length; ++i) {
      buffer[i] = in_string[i] ^ pad_[count_ % kPadSize_];
      ++count_;
    }

    return AttachedTransformation()->Put2(buffer.get(), length, message_end, blocking);
  }
  bool IsolatedFlush(bool, bool) { return false; }

 private:
  XORFilter &operator = (const XORFilter&);
  XORFilter(const XORFilter&);

  byte *pad_;
  size_t count_;
  const size_t kPadSize_;
};

// to allow safe cast from char -> byte
static_assert(std::is_same<std::uint8_t, unsigned char>::value ,
"This library requires std::uint8_t to be implemented as unsigned char.");

typedef std::vector<byte> Bytes;
typedef std::string Chars;
typedef std::map<uint64_t, Bytes> SequenceBlockMap;
//typedef SequenceBlockMap::value_type SequenceBlock;

Bytes CharToBytes(Chars&&chars);
Chars BytesToChars(Bytes&&);

crypto::CipherText EncryptDataMap(const Identity& parent_id,
                                  const Identity& this_id,
                                  const DataMap& data_map);

DataMap DecryptDataMap(const Identity& parent_id,
                       const Identity& this_id,
                       const std::string &encrypted_data_map);

//typedef std::function<ImmutableData(ImmutableData::Name)>
typedef std::string GetDataFromStore;



}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
