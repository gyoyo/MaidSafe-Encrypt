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



#include "maidsafe/encrypt/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/data_map.pb.h"

namespace maidsafe {

namespace encrypt {

// These conversions are guaranteed to be OK if using c++11 I believe std ref (3.10 : 10)
// (glvalue is a generalised value, i.e. lvalue or xvalue, so we should be fine)

// Quote from std
//if a program attempts to access the stored value of an object through a glvalue of
// other than one of the following types the behavior is undefined
//[snip]
//— a char or unsigned char type

Bytes CharToBytes(Chars&& chars) {
  Bytes bytes;
  bytes.reserve(chars.size());
  std::move(std::begin(chars), std::end(chars),
            std::back_inserter(bytes));
  return bytes;
}

Chars BytesToChars(Bytes&& bytes) {
  Chars chars;
  bytes.reserve(bytes.size());
  std::move(std::begin(bytes), std::end(bytes),
            std::back_inserter(chars));
  return chars;
}

crypto::CipherText EncryptDataMap(const Identity& parent_id,
                                  const Identity& this_id,
                                  const DataMap& data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));

  std::string serialised_data_map(SerialiseDataMap(data_map));

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  byte enc_hash[crypto::SHA512::DIGESTSIZE];
  byte xor_hash[crypto::SHA512::DIGESTSIZE];

  CryptoPP::SHA512().CalculateDigest(enc_hash,
                                     reinterpret_cast<const byte*>((parent_id.string() +
                                                                    this_id.string()).data()),
                                     inputs_size);
  CryptoPP::SHA512().CalculateDigest(xor_hash,
                                     reinterpret_cast<const byte*>((this_id.string() +
                                                                    parent_id.string()).data()),
                                     inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(
      enc_hash,
      crypto::AES256_KeySize,
      enc_hash + crypto::AES256_KeySize);
  std::string encrypted_data_map;
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(encryptor,
          new XORFilter(
              new CryptoPP::StringSink(encrypted_data_map),
              xor_hash,
              crypto::SHA512::DIGESTSIZE)),
      6);

    aes_filter.Put2(reinterpret_cast<const byte *>(serialised_data_map.c_str()),
                                             serialised_data_map.size(), -1, true);

  assert(!encrypted_data_map.empty());

  return crypto::CipherText(encrypted_data_map);
}

DataMap DecryptDataMap(const Identity& parent_id,
                    const Identity& this_id,
                    const std::string &encrypted_data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));

  std::string serialised_data_map;
  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  byte enc_hash[crypto::SHA512::DIGESTSIZE];
  byte xor_hash[crypto::SHA512::DIGESTSIZE];

  CryptoPP::SHA512().CalculateDigest(enc_hash,
                                      reinterpret_cast<const byte*>((parent_id.string() +
                                                                    this_id.string()).data()),
                                      inputs_size);
  CryptoPP::SHA512().CalculateDigest(xor_hash,
                                      reinterpret_cast<const byte*>((this_id.string() +
                                                                    parent_id.string()).data()),
                                      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(
      enc_hash,
      crypto::AES256_KeySize,
      enc_hash + crypto::AES256_KeySize);

  CryptoPP::StringSource filter(encrypted_data_map, true,
      new XORFilter(
          new CryptoPP::StreamTransformationFilter(
              decryptor,
              new CryptoPP::Gunzip(new CryptoPP::StringSink(serialised_data_map))),
          xor_hash,
          crypto::SHA512::DIGESTSIZE));

  return ParseDataMap(serialised_data_map);
}

}  // namespace encrypt

}  // namespace maidsafe
