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

#include "maidsafe/common/crypto.h"
#include "boost/shared_array.hpp"


namespace maidsafe {

namespace encrypt {
// to allow safe cast from char -> byte
static_assert(std::is_same<std::uint8_t, unsigned char>::value ,
"This library requires std::uint8_t to be implemented as unsigned char.");

typedef std::vector<byte> Bytes;
typedef std::vector<char> Chars;
typedef std::map<uint64_t, Bytes> SequenceBlockMap;
//typedef SequenceBlockMap::value_type SequenceBlock;

Bytes CharToBytes(Chars&&chars);
Chars BytesToChars(Bytes&&);


}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_UTILS_H_
