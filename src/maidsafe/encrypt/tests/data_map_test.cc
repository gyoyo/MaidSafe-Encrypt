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
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/tests/encrypt_test_base.h"

#include "catch.hpp"

#include "maidsafe/encrypt/utils.h"
#include "maidsafe/encrypt/data_map.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

TEST_CASE( "Data Map Basic construction", "[beh] [data_map]" ) {
  DataMap data_map1, data_map2, data_map3, data_map4;
  std::string test_string("abcdef");
  auto a = PostHash(Identity(crypto::Hash<crypto::SHA512>(std::string("a"))));
  auto b = PreHash(Identity(crypto::Hash<crypto::SHA512>(std::string("b"))));
  data_map1.chunks.emplace_back(a, b, 12);
  data_map2.chunks.emplace_back(a, b, 12);
  CHECK(data_map1 == data_map2);
  data_map2.chunks.emplace_back(a, b, 11);
  CHECK(data_map1 != data_map2);
  auto serialised_data_map = SerialiseDataMap(data_map1);
  CHECK_FALSE(serialised_data_map.empty());
  auto parsed_data_map = ParseDataMap(serialised_data_map);
  CHECK(data_map1 == parsed_data_map);
  // add content
  data_map1.content = test_string;
  CHECK(data_map1.content == test_string);
  CHECK(data_map1 != data_map2);
  serialised_data_map = SerialiseDataMap(data_map1);
  CHECK_FALSE(serialised_data_map.empty());
  auto parsed_data_map_with_content = ParseDataMap(serialised_data_map);
  CHECK(data_map1 == parsed_data_map_with_content);
  // content only
  data_map4.content = test_string;
  CHECK(data_map4.content == test_string);
  CHECK(data_map4 != data_map2);
  serialised_data_map = SerialiseDataMap(data_map4);
  CHECK_FALSE(serialised_data_map.empty());
  auto parsed_data_map_with_only_content = ParseDataMap(serialised_data_map);
  CHECK(data_map4 == parsed_data_map_with_only_content);
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
