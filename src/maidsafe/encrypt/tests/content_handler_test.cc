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

#include "catch.hpp"

#include "maidsafe/encrypt/utils.h"
#include "maidsafe/encrypt/content_handler.h"

namespace maidsafe {

namespace encrypt {

namespace test {

TEST_CASE( "Content Handler Basic construction", "[beh] [content_handler]") {
  ContentHandler content_handler;
  std::string test_string("asdfljk");
  CHECK_NOTHROW(content_handler.Write(test_string.data(), test_string.size() , 12));
  CHECK(content_handler.size() == 12  + static_cast<int64_t>(test_string.size()));
  CHECK(content_handler.Read(12, 7) == test_string);
  CHECK_NOTHROW(content_handler.Truncate(14));
  CHECK(content_handler.Read(12, 7) != std::string("as"));  // read past end spurious chars exist
  CHECK(std::string(content_handler.Read(12, 2),2) == std::string("as"));
  CHECK_NOTHROW(content_handler.Write(test_string.data(), test_string.size() , 12));
  CHECK(content_handler.size() == 19);
  CHECK_NOTHROW(content_handler.Write(test_string.data(), test_string.size() , 14));
  CHECK(content_handler.size() == 21);
  CHECK_NOTHROW(content_handler.Write(test_string.data(), test_string.size() , 34));
  CHECK(content_handler.size() == 41);
}

}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
