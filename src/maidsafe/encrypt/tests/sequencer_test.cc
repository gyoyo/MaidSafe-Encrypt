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
#include "maidsafe/encrypt/sequencer.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {

TEST_CASE( "Basic construction", "[beh] [sequencer]" ) {
  Sequencer sequencer;
  std::string test_string("asdfljk");
  CHECK_NOTHROW(sequencer.Write(test_string , 12));
  CHECK(sequencer.size() == test_string.size());
  CHECK(sequencer.Read(12, 7) == test_string);
  CHECK_NOTHROW(sequencer.Truncate(14));
  CHECK(sequencer.Read(12, 7) == "as");  // try and read past end
  CHECK(sequencer.Read(12, 2) == "as");
  CHECK(sequencer.Fetch(12, 7) == "as");  // try and read past end
  CHECK(sequencer.Fetch(12, 2).empty());
  CHECK(sequencer.Read(12, 0).empty());
  CHECK(sequencer.size() == 0);
  CHECK_NOTHROW(sequencer.Write(test_string , 12));
  CHECK(sequencer.size() == test_string.size());
  CHECK_NOTHROW(sequencer.Write(test_string , 14));
  CHECK(sequencer.size() == test_string.size() + 2U);
  CHECK_NOTHROW(sequencer.Write(test_string , 30));
  CHECK(sequencer.size() == ((test_string.size() * 2) + 2U));
}



}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
