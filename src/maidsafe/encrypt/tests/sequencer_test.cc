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

#include <thread>
#include <array>
#include <cstdlib>
#include <string>

#ifdef WIN32
#  pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/channels.h"
#include "cryptopp/gzip.h"
#include "cryptopp/ida.h"
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#ifdef WIN32
#  pragma warning(pop)
#endif
#include "boost/scoped_array.hpp"
#include "boost/filesystem.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/utils.h"
#include "maidsafe/encrypt/sequencer.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace test {





}  // namespace test

}  // namespace encrypt

}  // namespace maidsafe
