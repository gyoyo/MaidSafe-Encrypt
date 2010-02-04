/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-01-28-10.59.46
* Revision:     none
* Compiler:     gcc
* Author:       Team
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <maidsafe/contact_info.pb.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/clientrpc.h"
#include "maidsafe/client/maidstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultservice.h"

namespace test_msm {

void DoneRun(const int &min_delay,
             const int &max_delay,
             google::protobuf::Closure* callback) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int diff = max_delay - min;
  if (diff < 1)
    diff = 1;
  int sleep_time(base::random_32bit_uinteger() % diff + min);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  callback->Run();
}

void ThreadedDoneRun(const int &min_delay,
                     const int &max_delay,
                     google::protobuf::Closure* callback) {
  boost::thread(DoneRun, min_delay, max_delay, callback);
}

void ConditionNotifyNoFlag(int set_return,
                           int *return_value,
                           maidsafe::GenericConditionData *generic_cond_data) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(
      base::random_32bit_uinteger() % 1000 + 5000));
  boost::lock_guard<boost::mutex> lock(generic_cond_data->cond_mutex);
  *return_value = set_return;
  generic_cond_data->cond_variable->notify_all();
}

void FailedContactCallback(
    const kad::Contact &holder,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    boost::shared_ptr<maidsafe::GenericConditionData> cond_data) {
  int diff = max_delay - min_delay;
  int sleep_time(base::random_32bit_uinteger() % diff + min_delay);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  boost::shared_ptr<maidsafe::ChunkHolder> failed_chunkholder(
      new maidsafe::ChunkHolder(kad::Contact(holder.node_id(), "", 0)));
  failed_chunkholder->status = maidsafe::kFailedHolder;
  boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
  packet_holders->push_back(failed_chunkholder);
  cond_data->cond_variable->notify_all();
}

void ContactCallback(
    const kad::Contact &holder,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    boost::shared_ptr<maidsafe::GenericConditionData> cond_data) {
  int diff = max_delay - min_delay;
  int sleep_time(base::random_32bit_uinteger() % diff + min_delay);
  boost::this_thread::sleep(boost::posix_time::milliseconds(sleep_time));
  boost::shared_ptr<maidsafe::ChunkHolder>
      chunkholder(new maidsafe::ChunkHolder(holder));
  chunkholder->status = maidsafe::kContactable;
  boost::lock_guard<boost::mutex> lock(cond_data->cond_mutex);
  packet_holders->push_back(chunkholder);
  cond_data->cond_variable->notify_all();
}

void ThreadedGetHolderContactCallbacks(
    const std::vector<kad::Contact> &holders,
    const int &failures,
    const int &min_delay,
    const int &max_delay,
    std::vector< boost::shared_ptr<maidsafe::ChunkHolder> > *packet_holders,
    boost::shared_ptr<maidsafe::GenericConditionData> cond_data) {
  int min(min_delay);
  if (min < 0)
    min = 0;
  int max(max_delay);
  if (max - min < 1)
    max = min + 1;
  for (size_t i = 0, failed = 0; i < holders.size(); ++i) {
    // Add 500ms to each delay, to allow holders to callback in order
    min += 500;
    max += 500;
    if (static_cast<int>(failed) < failures) {
      boost::thread thr(FailedContactCallback, holders.at(i), min, max,
          packet_holders, cond_data);
      ++failed;
    } else {
      boost::thread thr(ContactCallback, holders.at(i), min, max,
          packet_holders, cond_data);
    }
  }
}

void AddToWatchListCallback(
    bool initialise_response,
    const int &result,
    const std::string &pmid,
    const boost::uint32_t &upload_count,
    maidsafe::AddToWatchListResponse *response,
    google::protobuf::Closure* callback) {
  if (initialise_response) {
    response->set_result(result);
    response->set_pmid(pmid);
    response->set_upload_count(upload_count);
  }
  callback->Run();
}

int SendChunkCount(int *send_chunk_count,
                   boost::mutex *mutex,
                   boost::condition_variable *cond_var) {
  boost::mutex::scoped_lock lock(*mutex);
  ++(*send_chunk_count);
  if (*send_chunk_count == 7)
    cond_var->notify_one();
  return 0;
}

void DelayedSetConnectionStatus(const int &status,
                                const int &delay,
                                maidsafe::SessionSingleton *ss) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(delay));
  ss->SetConnectionStatus(status);
}

void DelayedCancelTask(const std::string &chunkname,
                       const int &delay,
                       maidsafe::StoreTasksHandler *task_handler) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(delay));
  task_handler->CancelTask(chunkname, maidsafe::kStoreChunk);
}

void PacketOpCallback(const int &store_manager_result,
                      boost::mutex *mutex,
                      boost::condition_variable *cond_var,
                      int *op_result) {
  boost::mutex::scoped_lock lock(*mutex);
  *op_result = store_manager_result;
  cond_var->notify_one();
}

void RunDeletePacketCallbacks(
    std::list< boost::function < void(boost::shared_ptr<
        maidsafe::DeletePacketData>) > > functors,
    boost::shared_ptr<maidsafe::DeletePacketData> delete_data) {
  while (functors.size()) {
    functors.front()(delete_data);
    functors.pop_front();
  }
}

}  // namespace test_msm

namespace maidsafe {

class MaidStoreManagerTest : public testing::Test {
 protected:
  MaidStoreManagerTest() : test_root_dir_(file_system::FileSystem::TempDir() +
                                 "/maidsafe_TestMSM_" + base::RandomString(6)),
                           client_chunkstore_dir_(test_root_dir_+"/Chunkstore"),
                           client_chunkstore_(),
                           client_pmid_keys_(),
                           client_maid_keys_(),
                           client_pmid_public_signature_(),
                           hex_client_pmid_(),
                           client_pmid_(),
                           mutex_(),
                           crypto_(),
                           cond_var_(),
                           functor_(boost::bind(&test_msm::PacketOpCallback, _1,
                               &mutex_, &cond_var_, &packet_op_result_)) {
    try {
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest ctor - %s\n", e.what());
    }
    fs::create_directories(test_root_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
    client_maid_keys_.GenerateKeys(kRsaKeySize);
    std::string maid_pri = client_maid_keys_.private_key();
    std::string maid_pub = client_maid_keys_.public_key();
    std::string maid_pub_key_signature = crypto_.AsymSign(maid_pub, "",
        maid_pri, crypto::STRING_STRING);
    std::string maid_name = crypto_.Hash(maid_pub + maid_pub_key_signature, "",
        crypto::STRING_STRING, true);
    SessionSingleton::getInstance()->AddKey(MAID, maid_name, maid_pri, maid_pub,
        maid_pub_key_signature);
    client_pmid_keys_.GenerateKeys(kRsaKeySize);
    std::string pmid_pri = client_pmid_keys_.private_key();
    std::string pmid_pub = client_pmid_keys_.public_key();
    client_pmid_public_signature_ = crypto_.AsymSign(pmid_pub, "",
        maid_pri, crypto::STRING_STRING);
    hex_client_pmid_ = crypto_.Hash(pmid_pub +
        client_pmid_public_signature_, "", crypto::STRING_STRING, true);
    client_pmid_ = base::DecodeFromHex(hex_client_pmid_);
    SessionSingleton::getInstance()->AddKey(PMID, hex_client_pmid_, pmid_pri,
        pmid_pub, client_pmid_public_signature_);
    SessionSingleton::getInstance()->SetConnectionStatus(0);
  }

  virtual ~MaidStoreManagerTest() {
    try {
      SessionSingleton::getInstance()->ResetSession();
      boost::filesystem::remove_all(test_root_dir_);
    }
    catch(const std::exception &e) {
      printf("In MaidStoreManagerTest dtor - %s\n", e.what());
    }
  }

  virtual void SetUp() {
    client_chunkstore_ = boost::shared_ptr<ChunkStore>
        (new ChunkStore(client_chunkstore_dir_, 0, 0));
    ASSERT_TRUE(client_chunkstore_->Init());
    boost::uint64_t count(0);
    while (count < 60000 && !client_chunkstore_->is_initialised()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
  }
  virtual void TearDown() {}

  std::string test_root_dir_, client_chunkstore_dir_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  crypto::RsaKeyPair client_pmid_keys_, client_maid_keys_;
  std::string client_pmid_public_signature_, hex_client_pmid_, client_pmid_;
  boost::mutex mutex_;
  crypto::Crypto crypto_;
  boost::condition_variable cond_var_;
  int packet_op_result_;
  VoidFuncOneInt functor_;

 private:
  MaidStoreManagerTest(const MaidStoreManagerTest&);
  MaidStoreManagerTest &operator=(const MaidStoreManagerTest&);
};

class MockMsmKeyUnique : public MaidsafeStoreManager {
 public:
  explicit MockMsmKeyUnique(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD2(FindKNodes, int(const std::string &kad_key,
                               std::vector<kad::Contact> *contacts));
  MOCK_METHOD1(SendChunkPrep, int(const StoreData &store_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_KeyUnique) {
  MockMsmKeyUnique msm(client_chunkstore_);
  std::string non_hex_key = crypto_.Hash("a", "", crypto::STRING_STRING, false);
  std::string hex_key = base::EncodeToHex(non_hex_key);
  EXPECT_CALL(msm, FindValue(non_hex_key, true, testing::_, testing::_,
      testing::_)).WillOnce(testing::Return(1))
      .WillOnce(testing::Return(kSuccess));
  EXPECT_CALL(msm, FindValue(non_hex_key, false, testing::_, testing::_,
      testing::_)).WillOnce(testing::Return(1))
      .WillOnce(testing::Return(kSuccess));
  ASSERT_TRUE(msm.KeyUnique(hex_key, true));
  ASSERT_TRUE(msm.KeyUnique(hex_key, false));
  ASSERT_FALSE(msm.KeyUnique(hex_key, true));
  ASSERT_FALSE(msm.KeyUnique(hex_key, false));
}

class MockClientRpcs : public ClientRpcs {
 public:
  MockClientRpcs(transport::TransportHandler *transport_handler,
                 rpcprotocol::ChannelManager *channel_manager)
                     : ClientRpcs(transport_handler, channel_manager) {}
  MOCK_METHOD7(StorePrep, void(const kad::Contact &peer,
                               bool local,
                               const boost::int16_t &transport_id,
                               StorePrepRequest *store_prep_request,
                               StorePrepResponse *store_prep_response,
                               rpcprotocol::Controller *controller,
                               google::protobuf::Closure *done));
  MOCK_METHOD7(StoreChunk, void(const kad::Contact &peer,
                                bool local,
                                const boost::int16_t &transport_id,
                                StoreChunkRequest *store_chunk_request,
                                StoreChunkResponse *store_chunk_response,
                                rpcprotocol::Controller *controller,
                                google::protobuf::Closure *done));
  MOCK_METHOD7(AddToWatchList, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      AddToWatchListRequest *add_to_watch_list_request,
      AddToWatchListResponse *add_to_watch_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
  MOCK_METHOD7(RemoveFromWatchList, void(
      const kad::Contact &peer,
      bool local,
      const boost::int16_t &transport_id,
      RemoveFromWatchListRequest *remove_from_watch_list_request,
      RemoveFromWatchListResponse *remove_from_watch_list_response,
      rpcprotocol::Controller *controller,
      google::protobuf::Closure *done));
};

MATCHER_P(EqualsContact, kad_contact, "") {
  return (arg.node_id() == kad_contact.node_id() &&
          arg.host_ip() == kad_contact.host_ip() &&
          arg.host_port() == kad_contact.host_port());
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_AddToWatchList) {
  MockMsmKeyUnique msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  ASSERT_TRUE(client_chunkstore_->is_initialised());

  // Set up chunk
  std::string chunk_value = base::RandomString(396);
  std::string chunk_name = crypto_.Hash(chunk_value, "", crypto::STRING_STRING,
                                        false);
  std::string hex_chunk_name = base::EncodeToHex(chunk_name);
  ASSERT_EQ(kSuccess,
            client_chunkstore_->AddChunkToOutgoing(chunk_name, chunk_value));

  // Set up data for calls to FindKNodes
  std::vector<kad::Contact> chunk_info_holders, few_chunk_info_holders;
  for (boost::uint16_t i = 0; i < kad::K; ++i) {
    kad::Contact contact(crypto_.Hash(base::itos(i * i), "",
        crypto::STRING_STRING, false), "192.168.10." + base::itos(i), 8000 + i,
        "192.168.10." + base::itos(i), 8000 + i);
    chunk_info_holders.push_back(contact);
    if (i >= msm.kKadStoreThreshold_)
      few_chunk_info_holders.push_back(contact);
  }
  int send_chunk_count(0);
  boost::mutex mutex;
  boost::condition_variable cond_var;

  // Set expectations
  EXPECT_CALL(msm, FindKNodes(chunk_name, testing::_))
      .Times(9)
      .WillOnce(DoAll(testing::SetArgumentPointee<1>(chunk_info_holders),
          testing::Return(-1)))  // Call 1
      .WillOnce(DoAll(testing::SetArgumentPointee<1>(few_chunk_info_holders),
          testing::Return(kSuccess)))  // Call 2
      .WillRepeatedly(DoAll(testing::SetArgumentPointee<1>(chunk_info_holders),
          testing::Return(kSuccess)));

  // Contact Info holder 1
  EXPECT_CALL(*mock_rpcs, AddToWatchList(
      EqualsContact(chunk_info_holders.at(0)),
      testing::_,
      testing::_,
      testing::_,
      testing::_,
      testing::_,
      testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, false, kAck,
                chunk_info_holders.at(0).node_id(), 4, _1, _2))))  // Call 3
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kNack,
                chunk_info_holders.at(0).node_id(), 4, _1, _2))))  // Call 4
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(1).node_id(), 4, _1, _2))))  // Call 5
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(0).node_id(), kMinChunkCopies + 1, _1,
                _2))))  // Call 6
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(0).node_id(), 0, _1, _2))))  // Call 7
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(0).node_id(), 4, _1, _2))))  // Call 8
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(0).node_id(), 0, _1, _2))));  // Call 9

  // Contact Info holders 2 to 12 inclusive
  for (int i = 1; i < msm.kKadStoreThreshold_; ++i) {
    EXPECT_CALL(*mock_rpcs, AddToWatchList(
        EqualsContact(chunk_info_holders.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, false, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 3
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kNack,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 4
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i + 1).node_id(), 4, _1, _2))))  // Call 5
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), kMinChunkCopies + 1, _1,
                _2))))  // Call 6
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 0, _1, _2))))  // Call 7
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 8
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 3, _1, _2))));  // Call 9
  }

  // Contact Info holders 13 to 16 inclusive
  for (size_t i = msm.kKadStoreThreshold_; i < chunk_info_holders.size(); ++i) {
    EXPECT_CALL(*mock_rpcs, AddToWatchList(
        EqualsContact(chunk_info_holders.at(i)),
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_,
        testing::_))
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 3
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 4
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 5
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 6
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 0, _1, _2))))  // Call 7
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 4, _1, _2))))  // Call 8
            .WillOnce(testing::WithArgs<4, 6>(testing::Invoke(
                boost::bind(&test_msm::AddToWatchListCallback, true, kAck,
                chunk_info_holders.at(i).node_id(), 3, _1, _2))));  // Call 9
  }

  EXPECT_CALL(msm, SendChunkPrep(
      testing::AllOf(testing::Field(&StoreData::non_hex_key, chunk_name),
                     testing::Field(&StoreData::dir_type, PRIVATE))))
          .Times(7)  // Calls 8 (4 times) & 9 (3 times)
          .WillRepeatedly(testing::InvokeWithoutArgs(boost::bind(
              &test_msm::SendChunkCount, &send_chunk_count, &mutex,
              &cond_var)));

  // Run test calls
  // Call 1 - FindKNodes returns failure
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 2 - FindKNodes returns success but not enough contacts
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 3 - Five ATW responses return uninitialised
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 4 - Five ATW responses return kNack
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 5 - Five ATW responses return with wrong PMIDs
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 6 - Five ATW responses return excessive upload_count
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 7 - All ATW responses return upload_count of 0
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 8 - All ATW responses return upload_count of 4
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  // Call 9 - All ATW responses return upload_count of 3 except one which
  //          returns an upload_count of 0
  msm.StoreChunk(hex_chunk_name, PRIVATE, "");

  boost::mutex::scoped_lock lock(mutex);
  while (send_chunk_count < 7) {
    cond_var.wait(lock);
  }
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_AssessUploadCounts) {
  MaidsafeStoreManager msm(client_chunkstore_);

  // Set up test data
  const boost::uint64_t chunk_size(932);
  std::string chunk_value = base::RandomString(chunk_size);
  std::string chunk_name = crypto_.Hash(chunk_value, "", crypto::STRING_STRING,
                                        false);
  std::string hex_chunk_name = base::EncodeToHex(chunk_name);

  StoreData store_data(chunk_name, chunk_size, (kHashable | kNormal), PRIVATE,
      "", client_pmid_, client_pmid_keys_.public_key(),
      client_pmid_public_signature_, client_pmid_keys_.private_key());
  boost::shared_ptr<WatchListOpData>
      add_to_watchlist_data(new WatchListOpData(store_data));
  for (size_t i = 0; i < kad::K; ++i) {
    WatchListOpData::AddToWatchDataHolder
        hldr(crypto_.Hash(base::itos(i * i), "", crypto::STRING_STRING, false));
    add_to_watchlist_data->add_to_watchlist_data_holders.push_back(hldr);
  }

  // Run tests
  int test_run(0);

  // All return upload_copies == 2
  test_run = 1;
  for (int i = 0; i < msm.kKadStoreThreshold_ - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  for (size_t i = msm.kKadStoreThreshold_ - 1; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // All return upload_copies == 0
  test_run = 2;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < msm.kKadStoreThreshold_ - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(0);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  for (size_t i = msm.kKadStoreThreshold_ - 1; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(0);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 4 return 0, last 12 return 2.  Consensus should be 2.
  test_run = 3;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < kad::K - msm.kKadStoreThreshold_)
      add_to_watchlist_data->required_upload_copies.insert(0);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 11 return 2, next 4 return 1, last returns 0.  Consensus should be 0.
  test_run = 4;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < msm.kKadStoreThreshold_ - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  for (size_t i = msm.kKadStoreThreshold_ - 1; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(1);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(0);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesFailedConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
  }

  // First returns 0, next returns 1, others return 2.  Consensus should be 2.
  test_run = 5;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < msm.kKadStoreThreshold_ - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < 2)
      add_to_watchlist_data->required_upload_copies.insert(i);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  for (int i = msm.kKadStoreThreshold_ - 1; i < kad::K; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesFailedConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 10 return 2, last 6 return 1.  Consensus should be 2.
  test_run = 6;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = 0; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < msm.kKadStoreThreshold_ - 2)
      add_to_watchlist_data->required_upload_copies.insert(2);
    else
      add_to_watchlist_data->required_upload_copies.insert(1);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(1);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 10 return 1, last 6 return 2, chunk size == kMaxSmallChunkSize.
  // Consensus should be 2.
  test_run = 7;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  add_to_watchlist_data->store_data.size = kMaxSmallChunkSize;
  for (int i = 0; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < msm.kKadStoreThreshold_ - 2)
      add_to_watchlist_data->required_upload_copies.insert(1);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 10 return 1, last 6 return 2, chunk size > kMaxSmallChunkSize.
  // Consensus should be 1.
  test_run = 8;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  add_to_watchlist_data->store_data.size = kMaxSmallChunkSize + 1;
  for (int i = 0; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < msm.kKadStoreThreshold_ - 2)
      add_to_watchlist_data->required_upload_copies.insert(1);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(1, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 10 return 0, last 6 return 2, chunk size == kMaxSmallChunkSize.
  // Consensus should be 2.
  test_run = 9;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  add_to_watchlist_data->store_data.size = kMaxSmallChunkSize;
  for (int i = 0; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < msm.kKadStoreThreshold_ - 2)
      add_to_watchlist_data->required_upload_copies.insert(0);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // First 10 return 0, last 6 return 2, chunk size > kMaxSmallChunkSize.
  // Consensus should be 2.
  test_run = 10;
  add_to_watchlist_data->returned_count = 0;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  add_to_watchlist_data->store_data.size = kMaxSmallChunkSize + 1;
  for (int i = 0; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < msm.kKadStoreThreshold_ - 2)
      add_to_watchlist_data->required_upload_copies.insert(0);
    else
      add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // Only 5 return, all return 2.  Consensus should be 2.
  test_run = 11;
  add_to_watchlist_data->returned_count = msm.kKadStoreThreshold_ - 1;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = msm.kKadStoreThreshold_ - 1; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kSuccess, msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(2, add_to_watchlist_data->consensus_upload_copies);
  }

  // Only 5 return, two return 2, three return 1.  Consensus should be 0.
  test_run = 12;
  add_to_watchlist_data->returned_count = msm.kKadStoreThreshold_ - 1;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = msm.kKadStoreThreshold_ - 1; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    if (i < msm.kKadStoreThreshold_ + 1)
      add_to_watchlist_data->required_upload_copies.insert(2);
    else
      add_to_watchlist_data->required_upload_copies.insert(1);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(1);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesFailedConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
  }

  // Only 4 return, all return 2.  Consensus should be 0.
  test_run = 13;
  add_to_watchlist_data->returned_count = msm.kKadStoreThreshold_;
  add_to_watchlist_data->required_upload_copies.clear();
  add_to_watchlist_data->consensus_upload_copies = -1;
  for (int i = msm.kKadStoreThreshold_; i < kad::K - 1; ++i) {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " + base::itos(i));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesPendingConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(-1, add_to_watchlist_data->consensus_upload_copies);
  }
  {
    SCOPED_TRACE("Test " + base::itos(test_run) +" -- Resp " +
                 base::itos(kad::K - 1));
    add_to_watchlist_data->required_upload_copies.insert(2);
    ++add_to_watchlist_data->returned_count;
    ASSERT_EQ(kUploadCopiesFailedConsensus,
              msm.AssessUploadCounts(add_to_watchlist_data));
    ASSERT_EQ(0, add_to_watchlist_data->consensus_upload_copies);
  }
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests) {
  MaidsafeStoreManager msm(client_chunkstore_);
  std::string recipient_id = crypto_.Hash("RecipientID", "",
      crypto::STRING_STRING, false);
  // Make chunk/packet names
  std::vector<std::string> names;
  for (int i = 100; i < 104; ++i) {
    std::string j(base::itos(i));
    names.push_back(crypto_.Hash(j, "", crypto::STRING_STRING, false));
  }
  boost::shared_ptr<SendChunkData> send_chunk_data(
      new SendChunkData(StoreData(), kad::Contact(recipient_id, "", 0), true));
  StoreData &store_data = send_chunk_data->store_data;
  StorePrepRequest &store_prep_request = send_chunk_data->store_prep_request;
  StoreChunkRequest &store_chunk_request = send_chunk_data->store_chunk_request;

  // Check bad data - ensure existing parameters in requests are cleared
  store_prep_request.set_chunkname(names.at(0));
  store_chunk_request.set_chunkname(names.at(0));
  ASSERT_NE("", store_prep_request.chunkname());
  ASSERT_NE("", store_chunk_request.chunkname());
  std::string key_id2, public_key2, public_key_signature2, private_key2;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id2, &public_key2,
      &public_key_signature2, &private_key2);
  StoreData st_missing_name("", 10, (kHashable | kNormal), PRIVATE, "", key_id2,
      public_key2, public_key_signature2, private_key2);
  store_data = st_missing_name;
  ASSERT_EQ(kChunkNotInChunkstore, msm.GetStoreRequests(send_chunk_data));
  ASSERT_EQ("", store_prep_request.chunkname());
  ASSERT_EQ("", store_chunk_request.chunkname());

  // Check PRIVATE_SHARE chunk
  std::string msid_name = crypto_.Hash("b", "", crypto::STRING_STRING, true);
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(kRsaKeySize);
  std::vector<std::string> attributes;
  attributes.push_back("PrivateShare");
  attributes.push_back(msid_name);
  attributes.push_back(rsakp.public_key());
  attributes.push_back(rsakp.private_key());
  std::list<ShareParticipants> participants;
  ShareParticipants sp;
  sp.id = "spid";
  sp.public_key = "pub_key";
  sp.role = 'A';
  participants.push_back(sp);
  std::vector<boost::uint32_t> share_stats(2, 0);
  ASSERT_EQ(kSuccess, SessionSingleton::getInstance()->
      AddPrivateShare(attributes, share_stats, &participants));
  std::string key_id3, public_key3, public_key_signature3, private_key3;
  msm.GetChunkSignatureKeys(PRIVATE_SHARE, msid_name, &key_id3, &public_key3,
      &public_key_signature3, &private_key3);
  StoreData st_chunk_private_share(names.at(0), 3, (kHashable | kOutgoing),
      PRIVATE_SHARE, msid_name, key_id3, public_key3, public_key_signature3,
      private_key3);
  ASSERT_EQ(kSuccess,
      client_chunkstore_->AddChunkToOutgoing(names.at(0), std::string("100")));
  store_data = st_chunk_private_share;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  std::string public_key_signature = crypto_.AsymSign(rsakp.public_key(), "",
      rsakp.private_key(), crypto::STRING_STRING);
  std::string request_signature = crypto_.AsymSign(crypto_.Hash(
      public_key_signature + names.at(0) + recipient_id, "",
      crypto::STRING_STRING, false), "", rsakp.private_key(),
      crypto::STRING_STRING);
  std::string size_signature = crypto_.AsymSign(base::itos_ull(3), "",
      rsakp.private_key(), crypto::STRING_STRING);

  ASSERT_EQ(names.at(0), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(rsakp.public_key(), store_prep_request.signed_size().public_key());
  ASSERT_EQ(public_key_signature,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(0), store_chunk_request.chunkname());
  ASSERT_EQ("100", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(rsakp.public_key(), store_chunk_request.public_key());
  ASSERT_EQ(public_key_signature, store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());

  // Check PUBLIC_SHARE chunk
  std::string key_id4, public_key4, public_key_signature4, private_key4;
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_bad(names.at(1), 3, (kHashable | kOutgoing),
      PUBLIC_SHARE, "", key_id4, public_key4, public_key_signature4,
      private_key4);
  client_chunkstore_->AddChunkToOutgoing(names.at(1), std::string("101"));
  store_data = st_chunk_public_share_bad;
  ASSERT_EQ(kGetRequestSigError, msm.GetStoreRequests(send_chunk_data));
  rsakp.GenerateKeys(kRsaKeySize);
  std::string anmpid_pri = rsakp.private_key();
  std::string anmpid_pub = rsakp.public_key();
  std::string anmpid_pub_sig = crypto_.AsymSign(anmpid_pub, "", anmpid_pri,
      crypto::STRING_STRING);
  std::string anmpid_name = crypto_.Hash("Anmpid", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(ANMPID, anmpid_name, anmpid_pri,
      anmpid_pub, anmpid_pub_sig);
  rsakp.GenerateKeys(kRsaKeySize);
  std::string mpid_pri = rsakp.private_key();
  std::string mpid_pub = rsakp.public_key();
  std::string mpid_pub_sig = crypto_.AsymSign(mpid_pub, "",
      anmpid_pri, crypto::STRING_STRING);
  std::string mpid_name = crypto_.Hash("PublicName", "", crypto::STRING_STRING,
      true);
  SessionSingleton::getInstance()->AddKey(MPID, mpid_name, mpid_pri, mpid_pub,
      mpid_pub_sig);
  msm.GetChunkSignatureKeys(PUBLIC_SHARE, "", &key_id4, &public_key4,
      &public_key_signature4, &private_key4);
  StoreData st_chunk_public_share_good(names.at(1), 3, (kHashable | kOutgoing),
      PUBLIC_SHARE, "", key_id4, public_key4, public_key_signature4,
      private_key4);
  store_data = st_chunk_public_share_good;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      mpid_pub_sig + names.at(1) + recipient_id, "", crypto::STRING_STRING,
      false), "", mpid_pri, crypto::STRING_STRING);
  size_signature = crypto_.AsymSign(base::itos_ull(3), "", mpid_pri,
      crypto::STRING_STRING);

  ASSERT_EQ(names.at(1), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(mpid_pub, store_prep_request.signed_size().public_key());
  ASSERT_EQ(mpid_pub_sig,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(1), store_chunk_request.chunkname());
  ASSERT_EQ("101", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(mpid_pub, store_chunk_request.public_key());
  ASSERT_EQ(mpid_pub_sig, store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());

  // Check ANONYMOUS chunk
  std::string key_id5, public_key5, public_key_signature5, private_key5;
  msm.GetChunkSignatureKeys(ANONYMOUS, "", &key_id5, &public_key5,
      &public_key_signature5, &private_key5);
  StoreData st_chunk_anonymous(names.at(2), 3, (kHashable | kOutgoing),
      ANONYMOUS, "", key_id5, public_key5, public_key_signature5, private_key5);
  client_chunkstore_->AddChunkToOutgoing(names.at(2), std::string("102"));
  store_data = st_chunk_anonymous;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));

  ASSERT_EQ(names.at(2), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(" ", store_prep_request.signed_size().public_key());
  ASSERT_EQ(" ", store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(kAnonymousRequestSignature,
    store_prep_request.signed_size().signature());
  ASSERT_EQ(kAnonymousRequestSignature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(2), store_chunk_request.chunkname());
  ASSERT_EQ("102", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(" ", store_chunk_request.public_key());
  ASSERT_EQ(" ", store_chunk_request.public_key_signature());
  ASSERT_EQ(kAnonymousRequestSignature,
            store_chunk_request.request_signature());
  ASSERT_EQ(PDDIR_NOTSIGNED, store_chunk_request.data_type());

  // Check PRIVATE chunk
  std::string key_id6, public_key6, public_key_signature6, private_key6;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id6, &public_key6,
      &public_key_signature6, &private_key6);
  StoreData st_chunk_private(names.at(3), 3, (kHashable | kOutgoing), PRIVATE,
      "", key_id6, public_key6, public_key_signature6, private_key6);
  client_chunkstore_->AddChunkToOutgoing(names.at(3), std::string("103"));
  store_data = st_chunk_private;
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  request_signature = crypto_.AsymSign(crypto_.Hash(
      client_pmid_public_signature_ + names.at(3) + recipient_id, "",
      crypto::STRING_STRING, false), "", client_pmid_keys_.private_key(),
      crypto::STRING_STRING);
  size_signature = crypto_.AsymSign(base::itos_ull(3), "",
      client_pmid_keys_.private_key(), crypto::STRING_STRING);

  ASSERT_EQ(names.at(3), store_prep_request.chunkname());
  ASSERT_EQ(size_t(3), store_prep_request.signed_size().data_size());
  ASSERT_EQ(client_pmid_, store_prep_request.signed_size().pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(),
      store_prep_request.signed_size().public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_prep_request.signed_size().public_key_signature());
  ASSERT_EQ(size_signature, store_prep_request.signed_size().signature());
  ASSERT_EQ(request_signature, store_prep_request.request_signature());

  ASSERT_EQ(names.at(3), store_chunk_request.chunkname());
  ASSERT_EQ("103", store_chunk_request.data());
  ASSERT_EQ(client_pmid_, store_chunk_request.pmid());
  ASSERT_EQ(client_pmid_keys_.public_key(), store_chunk_request.public_key());
  ASSERT_EQ(client_pmid_public_signature_,
      store_chunk_request.public_key_signature());
  ASSERT_EQ(request_signature, store_chunk_request.request_signature());
  ASSERT_EQ(DATA, store_chunk_request.data_type());
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_ValidatePrepResp) {
  MaidsafeStoreManager msm(client_chunkstore_);
  // Make peer keys
  crypto::RsaKeyPair peer_pmid_keys;
  peer_pmid_keys.GenerateKeys(kRsaKeySize);
  std::string peer_pmid_pri = peer_pmid_keys.private_key();
  std::string peer_pmid_pub = peer_pmid_keys.public_key();
  std::string peer_pmid_pub_signature = crypto_.AsymSign(peer_pmid_pub, "",
      peer_pmid_pri, crypto::STRING_STRING);
  std::string peer_pmid = crypto_.Hash(peer_pmid_pub + peer_pmid_pub_signature,
      "", crypto::STRING_STRING, false);
  // Make request
  std::string chunk_value(base::RandomString(163));
  std::string chunk_name(crypto_.Hash(chunk_value, "", crypto::STRING_STRING,
      false));
  StoreData store_data(chunk_name, chunk_value.size(), (kHashable | kOutgoing),
      PRIVATE, "", client_pmid_, client_pmid_keys_.public_key(),
      client_pmid_public_signature_, client_pmid_keys_.private_key());
  client_chunkstore_->AddChunkToOutgoing(chunk_name, chunk_value);
  boost::shared_ptr<SendChunkData> send_chunk_data(
      new SendChunkData(store_data, kad::Contact(peer_pmid, "", 0), true));
  ASSERT_EQ(kSuccess, msm.GetStoreRequests(send_chunk_data));
  StorePrepRequest store_prep_request = send_chunk_data->store_prep_request;
  StoreChunkRequest store_chunk_request = send_chunk_data->store_chunk_request;
  // Make proper response
  maidsafe_vault::VaultChunkStore
      vault_chunkstore(test_root_dir_ + "/VaultChunkstore", 999999, 0);
  maidsafe_vault::VaultService vault_service(peer_pmid_pub, peer_pmid_pri,
      peer_pmid_pub_signature, &vault_chunkstore, NULL, NULL, NULL, 0);
  StorePrepResponse good_store_prep_response;
  google::protobuf::Closure *done =
      google::protobuf::NewCallback(&google::protobuf::DoNothing);
  vault_service.StorePrep(NULL, &store_prep_request,
                          &good_store_prep_response, done);

  // Uninitialised StorePrepResponse
  StorePrepResponse store_prep_response;
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Uninitialised StoreContract
  store_prep_response = good_store_prep_response;
  store_prep_response.clear_store_contract();
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Uninitialised InnerContract
  store_prep_response = good_store_prep_response;
  StoreContract *mutable_store_contract =
      store_prep_response.mutable_store_contract();
  mutable_store_contract->clear_inner_contract();
  ASSERT_EQ(kSendPrepResponseUninitialised, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Wrong PMID
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_store_contract->set_pmid(client_pmid_);
  ASSERT_EQ(kSendPrepPeerError, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Altered SignedSize
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  StoreContract::InnerContract *mutable_inner_contract =
      mutable_store_contract->mutable_inner_contract();
  SignedSize *mutable_signed_size =
      mutable_inner_contract->mutable_signed_size();
  mutable_signed_size->set_data_size(chunk_value.size() - 1);
  ASSERT_EQ(kSendPrepSignedSizeAltered, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // Returned kNack
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_inner_contract = mutable_store_contract->mutable_inner_contract();
  mutable_inner_contract->set_result(kNack);
  ASSERT_EQ(kSendPrepFailure, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // PMID doesn't validate
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  std::string wrong_pmid = crypto_.Hash(base::RandomString(100), "",
      crypto::STRING_STRING, false);
  mutable_store_contract->set_pmid(wrong_pmid);
  ASSERT_EQ(kSendPrepInvalidId, msm.ValidatePrepResponse(wrong_pmid,
      store_prep_request.signed_size(), &store_prep_response));

  // PMID didn't sign StoreContract correctly
  store_prep_response = good_store_prep_response;
  store_prep_response.set_response_signature(crypto_.AsymSign(
      base::RandomString(100), "", peer_pmid_pri, crypto::STRING_STRING));
  ASSERT_EQ(kSendPrepInvalidResponseSignature, msm.ValidatePrepResponse(
      peer_pmid, store_prep_request.signed_size(), &store_prep_response));

  // PMID didn't sign InnerContract correctly
  store_prep_response = good_store_prep_response;
  mutable_store_contract = store_prep_response.mutable_store_contract();
  mutable_store_contract->set_signature(crypto_.AsymSign(base::RandomString(99),
      "", peer_pmid_pri, crypto::STRING_STRING));
  std::string ser_bad_contract;
  mutable_store_contract->SerializeToString(&ser_bad_contract);
  store_prep_response.set_response_signature(crypto_.AsymSign(ser_bad_contract,
      "", peer_pmid_pri, crypto::STRING_STRING));
  ASSERT_EQ(kSendPrepInvalidContractSignature, msm.ValidatePrepResponse(
      peer_pmid, store_prep_request.signed_size(), &store_prep_response));

  // All OK
  ASSERT_EQ(kSuccess, msm.ValidatePrepResponse(peer_pmid,
      store_prep_request.signed_size(), &good_store_prep_response));
}

class MockMsmSendChunkPrep : public MaidsafeStoreManager {
 public:
  explicit MockMsmSendChunkPrep(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD3(AssessTaskStatus, TaskStatus(const std::string &data_name,
                                            StoreTaskType task_type,
                                            StoreTask *task));
  MOCK_METHOD4(GetStorePeer, int(const float &ideal_rtt,
                                 const std::vector<kad::Contact> &exclude,
                                 kad::Contact *new_peer,
                                 bool *local));
  MOCK_METHOD2(WaitForOnline, bool(const std::string &data_name,
                                   const StoreTaskType &task_type));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkPrep) {
  // Set up test data
  MockMsmSendChunkPrep msm(client_chunkstore_);
  std::string chunkname = crypto_.Hash("ddd", "", crypto::STRING_STRING, false);
  std::string hex_chunkname = base::EncodeToHex(chunkname);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("ddd"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());

  // Set up expectations
  EXPECT_CALL(msm, AssessTaskStatus(testing::_, kStoreChunk, testing::_))
      .Times(6)
      .WillOnce(testing::Return(kCompleted))  // Call 1
      .WillOnce(testing::Return(kCancelled))  // Call 2
      .WillOnce(testing::Return(kPending))  // Call 3
      .WillRepeatedly(testing::Return(kStarted));

  EXPECT_CALL(msm, GetStorePeer(testing::_, testing::_, testing::_, testing::_))
      .WillOnce(testing::Return(kGetStorePeerError))  // Call 3
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(peer),  // Call 4
                      testing::InvokeWithoutArgs(boost::bind(
                          &StoreTasksHandler::DeleteTask, &msm.tasks_handler_,
                          store_data.non_hex_key, kStoreChunk,
                          kStoreCancelledOrDone))))
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(peer),
                      testing::Return(kSuccess)))  // Call 5
      .WillOnce(DoAll(testing::SetArgumentPointee<2>(peer),
                      testing::Return(kSuccess)));  // Call 6

  EXPECT_CALL(msm, WaitForOnline(chunkname, kStoreChunk))
      .WillOnce(testing::Return(false))  // Call 5
      .WillOnce(testing::Return(true));  // Call 6

  // Run tests
  // Call 1
  ASSERT_EQ(kStoreCancelledOrDone, msm.SendChunkPrep(store_data));

  // Call 2 - should cause the task to be removed
  ASSERT_EQ(kStoreCancelledOrDone, msm.SendChunkPrep(store_data));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 3
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kGetStorePeerError, msm.SendChunkPrep(store_data));

  // Call 4 - GetStorePeer call sneakily deletes the task before it's started
  ASSERT_EQ(kSendChunkFailure, msm.SendChunkPrep(store_data));

  // Call 5
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(store_data.non_hex_key,
      kStoreChunk, store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kTaskCancelledOffline, msm.SendChunkPrep(store_data));

  // Call 6
  ASSERT_EQ(kSuccess, msm.SendChunkPrep(store_data));
}

class MockMsmSendPrepCallback : public MaidsafeStoreManager {
 public:
  explicit MockMsmSendPrepCallback(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD3(ValidatePrepResponse, int(
      const std::string &peer_node_id,
      const SignedSize &request_signed_size,
      StorePrepResponse *const store_prep_response));
  MOCK_METHOD1(SendChunkContent, int(
      boost::shared_ptr<SendChunkData> send_chunk_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendPrepCallback) {
  // Set up test data
  MockMsmSendPrepCallback msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  std::string chunkname = crypto_.Hash("eee", "", crypto::STRING_STRING, false);
  std::string hex_chunkname = base::EncodeToHex(chunkname);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("eee"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, kMaxStoreFailures));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(0));
  boost::shared_ptr<SendChunkData>
      send_chunk_data(new SendChunkData(store_data, peer, true));

  // Set up expectations
  EXPECT_CALL(msm, ValidatePrepResponse(peername, testing::_, testing::_))
      .Times(5)
      .WillOnce(testing::Return(kSuccess))  // Call 1
      .WillRepeatedly(testing::Return(-1));

  EXPECT_CALL(msm, SendChunkContent(testing::_));  // Call 1

  EXPECT_CALL(*mock_rpcs, StorePrep(EqualsContact(peer), testing::_, testing::_,
      testing::_, testing::_, testing::_, testing::_))
          .Times(1);  // Call 2

  // Run tests
  // Call 1 - All OK
  msm.SendPrepCallback(send_chunk_data);
  StoreTask retrieved_task;
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);
  ASSERT_EQ(1, send_chunk_data->attempt);

  // Call 2 - Validation of store_contract fails and we're now offline.  Once
  // online, task is still valid.
  send_chunk_data->attempt = 0;
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(1));
  boost::thread thr1(&test_msm::DelayedSetConnectionStatus, 0, 3000, msm.ss_);
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(1, send_chunk_data->attempt);
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 3 - Validation of store_contract fails and we're now offline.  Once
  // online, task has been cancelled.
  send_chunk_data->attempt = 0;
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(1));
  boost::thread thr2(&test_msm::DelayedSetConnectionStatus, 0, 3000, msm.ss_);
  boost::thread thr3(&test_msm::DelayedCancelTask, chunkname, 1500,
      &msm.tasks_handler_);
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(1, send_chunk_data->attempt);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 4 - Validation of store_contract fails and task has been cancelled.
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.tasks_handler_.CancelTask(store_data.non_hex_key,
      kStoreChunk));
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(1, send_chunk_data->attempt);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 5 - Validation of store_contract fails on final attempt.
  send_chunk_data->attempt = kMaxChunkStoreTries - 1;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  msm.SendPrepCallback(send_chunk_data);
  ASSERT_EQ(kMaxChunkStoreTries, send_chunk_data->attempt);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkContent) {
  MaidsafeStoreManager msm(client_chunkstore_);
  boost::shared_ptr<MockClientRpcs> mock_rpcs(
      new MockClientRpcs(&msm.transport_handler_, &msm.channel_manager_));
  msm.client_rpcs_ = mock_rpcs;
  std::string chunkname = crypto_.Hash("fff", "", crypto::STRING_STRING, false);
  std::string hex_chunkname = base::EncodeToHex(chunkname);
  client_chunkstore_->AddChunkToOutgoing(chunkname, std::string("fff"));
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetChunkSignatureKeys(PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  StoreData store_data(chunkname, 3, (kHashable | kOutgoing), PRIVATE, "",
      key_id, public_key, public_key_signature, private_key);
  std::string peername = crypto_.Hash("peer", "", crypto::STRING_STRING, false);
  kad::Contact peer(peername, "192.192.1.1", 9999);
  ASSERT_TRUE(msm.ss_->SetConnectionStatus(0));
  boost::shared_ptr<SendChunkData>
      send_chunk_data(new SendChunkData(store_data, peer, true));

  // Set up expectations
  EXPECT_CALL(*mock_rpcs, StoreChunk(EqualsContact(peer), testing::_,
      testing::_, testing::_, testing::_, testing::_, testing::_))
          .Times(3);  // Calls 2, 3, & 5

  // Run tests
  // Call 1 - Task cancelled before sending RPC
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.CancelTask(chunkname, kStoreChunk));
  ASSERT_EQ(kStoreCancelledOrDone, msm.SendChunkContent(send_chunk_data));
  StoreTask retrieved_task;
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 2 - SendChunkContent success
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_EQ(kSuccess, msm.SendChunkContent(send_chunk_data));
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 3 - Callback with unitialised response - task still active
  send_chunk_data->attempt = 0;
  msm.SendContentCallback(send_chunk_data);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 4 - Callback with unitialised response - task cancelled
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.CancelTask(chunkname, kStoreChunk));
  msm.SendContentCallback(send_chunk_data);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 5 - Callback with wrong PMID - task still active
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  StoreChunkResponse &response = send_chunk_data->store_chunk_response;
  response.set_result(kAck);
  response.set_pmid(chunkname);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.active_subtask_count_);

  // Call 6 - Callback with kNack - last attempt
  send_chunk_data->attempt = kMaxChunkStoreTries - 1;
  response.set_result(kNack);
  response.set_pmid(peername);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());

  // Call 7 - Callback OK - only one chunk copy required
  send_chunk_data->attempt = 0;
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, 1, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  response.set_result(kAck);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_FALSE(msm.tasks_handler_.Task(chunkname, kStoreChunk,
               &retrieved_task));
  ASSERT_EQ(size_t(0), msm.tasks_handler_.TasksCount());
  ChunkType chunk_type = msm.client_chunkstore_->chunk_type(chunkname);
  ASSERT_EQ((kHashable | kNormal), chunk_type);

  // Call 8 - Callback OK - kMinChunkCopies required
  send_chunk_data->attempt = 0;
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  ASSERT_EQ(kSuccess, client_chunkstore_->ChangeChunkType(chunkname, new_type));
  ASSERT_EQ((kHashable | kOutgoing),
            msm.client_chunkstore_->chunk_type(chunkname));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.AddTask(chunkname, kStoreChunk,
      store_data.size, kMinChunkCopies, 1));
  ASSERT_EQ(kSuccess, msm.tasks_handler_.StartSubTask(chunkname, kStoreChunk,
      peer));
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  response.set_result(kAck);
  msm.SendContentCallback(send_chunk_data);
  ASSERT_EQ(size_t(1), msm.tasks_handler_.TasksCount());
  ASSERT_TRUE(msm.tasks_handler_.Task(chunkname, kStoreChunk, &retrieved_task));
  ASSERT_EQ(boost::uint8_t(0), retrieved_task.active_subtask_count_);
  ASSERT_EQ(boost::uint8_t(1), retrieved_task.success_count_);
  ASSERT_EQ((kHashable | kNormal),
            msm.client_chunkstore_->chunk_type(chunkname));
}

class MockMsmStoreLoadPacket : public MaidsafeStoreManager {
 public:
  explicit MockMsmStoreLoadPacket(boost::shared_ptr<ChunkStore> cstore)
      : MaidsafeStoreManager(cstore) {}
  MOCK_METHOD5(FindValue, int(const std::string &kad_key,
                              bool check_local,
                              kad::ContactInfo *cache_holder,
                              std::vector<std::string> *chunk_holders_ids,
                              std::string *needs_cache_copy_id));
  MOCK_METHOD1(SendPacket, void(boost::shared_ptr<StoreData> store_data));
  MOCK_METHOD1(DeletePacketFromNet,
               void(boost::shared_ptr<DeletePacketData> delete_data));
};

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StoreNewPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for storing
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string hex_packet_name = base::EncodeToHex(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  std::string packet_value = base::RandomString(200);

  // Set up test requirements
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");
  std::string ser_kad_store_response_cant_parse("Rubbish");
  std::string ser_kad_store_response_empty;
  std::string ser_kad_store_response_good, ser_kad_store_response_fail;
  kad::StoreResponse store_response;
  store_response.set_result(kad::kRpcResultSuccess);
  store_response.SerializeToString(&ser_kad_store_response_good);
  store_response.set_result("Fail");
  store_response.SerializeToString(&ser_kad_store_response_fail);

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_name, true, testing::_, testing::_,
      testing::_))
          .Times(6)
          .WillOnce(testing::Return(-1))  // Call 3
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(kSuccess)))  // Call 4
          .WillRepeatedly(testing::Return(kFindValueFailure));

  EXPECT_CALL(msm, SendPacket(testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_empty, _1))))  // Call 5
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_cant_parse, _1))))  // Call 6
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_fail, _1))))  // Call 7
      .WillOnce(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_good, _1))));  // Call 8

  // Call 1 - Check with bad packet name length
  packet_op_result_ = kGeneralError;
  msm.StorePacket("InvalidName", packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kIncorrectKeySize, packet_op_result_);

  // Call 2 - Check with bad packet type
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, static_cast<PacketType>(-1),
                  PRIVATE, "", kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kPacketUnknownType, packet_op_result_);

  // Call 3 - FindValue fails
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketFindValueFailure, packet_op_result_);

  // Call 4 - FindValue yields a cached copy
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketCached, packet_op_result_);

  // Call 5 - SendPacket returns no result
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketError, packet_op_result_);

  // Call 6 - SendPacket returns unparseable result
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketParseError, packet_op_result_);

  // Call 7 - SendPacket returns failure
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketFailure, packet_op_result_);

  // Call 8 - SendPacket returns success
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_StoreExistingPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for storing
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string hex_packet_name = base::EncodeToHex(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  std::string packet_value = base::RandomString(200);

  // Set up store response
  std::string ser_kad_store_response_good;
  kad::StoreResponse store_response;
  store_response.set_result(kad::kRpcResultSuccess);
  store_response.SerializeToString(&ser_kad_store_response_good);

  // Set up serialised Kademlia delete responses
  std::string ser_kad_delete_response_cant_parse("Rubbish");
  std::string ser_kad_delete_response_empty;
  std::string ser_kad_delete_response_good, ser_kad_delete_response_fail;
  kad::DeleteResponse delete_response;
  delete_response.set_result(kad::kRpcResultSuccess);
  delete_response.SerializeToString(&ser_kad_delete_response_good);
  delete_response.set_result("Fail");
  delete_response.SerializeToString(&ser_kad_delete_response_fail);

  // Set up lists of DeletePacketCallbacks using serialised Kad delete responses
  const size_t kExistingValueCount(5);
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_good;
  for (size_t i = 0; i < kExistingValueCount - 1; ++i) {
    functors_kad_good.push_back(boost::bind(
        &MaidsafeStoreManager::DeletePacketCallback, &msm,
        ser_kad_delete_response_good, _1));
  }
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_empty(functors_kad_good),
      functors_kad_cant_parse(functors_kad_good),
      functors_kad_fail(functors_kad_good);
  functors_kad_empty.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_empty, _1));
  functors_kad_cant_parse.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_cant_parse, _1));
  functors_kad_fail.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_fail, _1));
  functors_kad_good.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_good, _1));

  // Set up vector of existing values
  std::vector<std::string> existing_values;
  for (size_t i = 0; i < kExistingValueCount; ++i)
    existing_values.push_back("ExistingValue" + base::itos(i));

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_name, true, testing::_, testing::_,
      testing::_))
          .Times(8)
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<3>(existing_values),
                                testing::Return(kSuccess)));

  EXPECT_CALL(msm, SendPacket(testing::_))
      .Times(2)
      .WillRepeatedly(testing::WithArgs<0>(testing::Invoke(
          boost::bind(&MaidsafeStoreManager::SendPacketCallback, &msm,
          ser_kad_store_response_good, _1))));  // Calls 3 & 8

  EXPECT_CALL(msm, DeletePacketFromNet(testing::_))  // Calls 5 to 8 inclusive
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_empty, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_cant_parse, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_fail, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))));

  // Call 1 - If exists kDoNothingReturnFailure
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnFailure, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketAlreadyExists, packet_op_result_);

  // Call 2 - If exists kDoNothingReturnSuccess
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  kDoNothingReturnSuccess, functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 3 - If exists kAppend
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kAppend,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 4 - Invalid IfExists
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "",
                  static_cast<IfPacketExists>(-1), functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSendPacketUnknownExistsType, packet_op_result_);

  // Call 5 - If exists kOverwrite - DeleteResponse empty
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketError, packet_op_result_);

  // Call 6 - If exists kOverwrite - DeleteResponse doesn't parse
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketParseError, packet_op_result_);

  // Call 7 - If exists kOverwrite - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 8 - If exists kOverwrite - DeleteResponse passes
  packet_op_result_ = kGeneralError;
  msm.StorePacket(hex_packet_name, packet_value, MID, PRIVATE, "", kOverwrite,
                  functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_LoadPacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Set up test requirements
  std::vector<std::string> packet_names, hex_packet_names;
  const size_t kTestCount(6);
  packet_names.push_back("InvalidName");
  hex_packet_names.push_back("InvalidName");
  for (size_t i = 1; i < kTestCount; ++i) {
    packet_names.push_back(crypto_.Hash(base::RandomString(100), "",
                                        crypto::STRING_STRING, false));
    hex_packet_names.push_back(base::EncodeToHex(packet_names.at(i)));
  }
  std::vector<std::string> values, returned_values;
  const size_t kValueCount(5);
  for (size_t i = 0; i < kValueCount; ++i)
    values.push_back("Value" + base::itos(i));
  kad::ContactInfo cache_holder;
  cache_holder.set_node_id("a");

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_names.at(1), false, testing::_, testing::_,
      testing::_))
          .Times(kMaxChunkLoadRetries)
          .WillRepeatedly(testing::Return(-1));  // Call 2

  EXPECT_CALL(msm, FindValue(packet_names.at(2), false, testing::_, testing::_,
      testing::_))
          .Times(kMaxChunkLoadRetries)
          .WillRepeatedly(testing::Return(kSuccess));  // Call 3

  EXPECT_CALL(msm, FindValue(packet_names.at(3), false, testing::_, testing::_,
      testing::_))
          .Times(kMaxChunkLoadRetries)
          .WillRepeatedly(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                                testing::Return(kSuccess)));  // Call 4

  EXPECT_CALL(msm, FindValue(packet_names.at(4), false, testing::_, testing::_,
      testing::_))  // Call 5
          .WillOnce(testing::Return(-1))
          .WillOnce(DoAll(testing::SetArgumentPointee<2>(cache_holder),
                          testing::Return(kSuccess)))
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(values),
                          testing::Return(kSuccess)));

  EXPECT_CALL(msm, FindValue(packet_names.at(5), false, testing::_, testing::_,
      testing::_))  // Call 6
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(values),
                          testing::Return(kSuccess)));

  // Call 1 - Check with bad packet name length
  size_t test_number(0);
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kIncorrectKeySize,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 2 - FindValue fails
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 3 - FindValue claims success but doesn't populate value vector
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 4 - FindValue yields a cached copy
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kFindValueFailure,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(0), returned_values.size());

  // Call 5 - Success
  ++test_number;
  returned_values.push_back("Val");
  ASSERT_EQ(size_t(1), returned_values.size());
  ASSERT_EQ(kSuccess,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_values));
  ASSERT_EQ(size_t(kValueCount), returned_values.size());
  for (size_t i = 0; i < kValueCount; ++i)
    ASSERT_EQ(values.at(i), returned_values.at(i));

  // Call 6 - Single value success
  ++test_number;
  std::string returned_value("Fud");
  ASSERT_EQ(kSuccess,
            msm.LoadPacket(hex_packet_names.at(test_number), &returned_value));
  ASSERT_EQ(values.at(0), returned_value);
}

TEST_F(MaidStoreManagerTest, BEH_MAID_MSM_DeletePacket) {
  MockMsmStoreLoadPacket msm(client_chunkstore_);

  // Add keys to Session
  crypto::RsaKeyPair anmid_keys;
  anmid_keys.GenerateKeys(kRsaKeySize);
  std::string anmid_pri = anmid_keys.private_key();
  std::string anmid_pub = anmid_keys.public_key();
  std::string anmid_pub_key_signature = crypto_.AsymSign(anmid_pub, "",
      anmid_pri, crypto::STRING_STRING);
  std::string anmid_name = crypto_.Hash(anmid_pub + anmid_pub_key_signature, "",
      crypto::STRING_STRING, true);
  SessionSingleton::getInstance()->AddKey(ANMID, anmid_name, anmid_pri,
      anmid_pub, anmid_pub_key_signature);

  // Set up packet for deletion
  std::string packet_name = crypto_.Hash(base::RandomString(100), "",
                                         crypto::STRING_STRING, false);
  std::string hex_packet_name = base::EncodeToHex(packet_name);
  std::string key_id, public_key, public_key_signature, private_key;
  msm.GetPacketSignatureKeys(MID, PRIVATE, "", &key_id, &public_key,
      &public_key_signature, &private_key);
  ASSERT_EQ(anmid_name, key_id);
  ASSERT_EQ(anmid_pub, public_key);
  ASSERT_EQ(anmid_pub_key_signature, public_key_signature);
  ASSERT_EQ(anmid_pri, private_key);
  const size_t kValueCount(5);
  std::vector<std::string> packet_values, single_value;
  for (size_t i = 0; i < kValueCount; ++i)
    packet_values.push_back("Value" + base::itos(i));
  single_value.push_back("Value");

  // Set up serialised Kademlia delete responses
  std::string ser_kad_delete_response_cant_parse("Rubbish");
  std::string ser_kad_delete_response_empty;
  std::string ser_kad_delete_response_good, ser_kad_delete_response_fail;
  kad::DeleteResponse delete_response;
  delete_response.set_result(kad::kRpcResultSuccess);
  delete_response.SerializeToString(&ser_kad_delete_response_good);
  delete_response.set_result("Fail");
  delete_response.SerializeToString(&ser_kad_delete_response_fail);

  // Set up lists of DeletePacketCallbacks using serialised Kad delete responses
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_good;
  for (size_t i = 0; i < kValueCount - 1; ++i) {
    functors_kad_good.push_back(boost::bind(
        &MaidsafeStoreManager::DeletePacketCallback, &msm,
        ser_kad_delete_response_good, _1));
  }
  std::list< boost::function< void(boost::shared_ptr<DeletePacketData>) > >
      functors_kad_empty(functors_kad_good),
      functors_kad_cant_parse(functors_kad_good),
      functors_kad_fail(functors_kad_good);
  functors_kad_empty.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_empty, _1));
  functors_kad_cant_parse.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_cant_parse, _1));
  functors_kad_fail.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_fail, _1));
  functors_kad_good.push_back(boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, &msm,
      ser_kad_delete_response_good, _1));

  // Set up expectations
  EXPECT_CALL(msm, FindValue(packet_name, false, testing::_, testing::_,
      testing::_))
          .Times(5)
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(single_value),
                          testing::Return(kSuccess)))  // Call 9
          .WillOnce(testing::Return(kFindNodesFailure))  // Call 10
          .WillOnce(testing::Return(-1))  // Call 11
          .WillOnce(testing::Return(kSuccess))  // Call 12
          .WillOnce(DoAll(testing::SetArgumentPointee<3>(packet_values),
                          testing::Return(kSuccess)));  // Call 13

  EXPECT_CALL(msm, DeletePacketFromNet(testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_empty, _1))))  // 3
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_cant_parse, _1))))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_fail, _1))))  // 5
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))))  // 6
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &MaidsafeStoreManager::DeletePacketCallback, &msm,
          ser_kad_delete_response_fail, _1))))  // Call 7
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &MaidsafeStoreManager::DeletePacketCallback, &msm,
          ser_kad_delete_response_good, _1))))  // Call 8
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))))  // 9
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(
          &test_msm::RunDeletePacketCallbacks, functors_kad_good, _1))));  // 13

  // Call 1 - Check with bad packet name length
  packet_op_result_ = kGeneralError;
  msm.DeletePacket("InvalidName", packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kIncorrectKeySize, packet_op_result_);

  // Call 2 - Invalid PacketType
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, static_cast<PacketType>(-1),
                   PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kPacketUnknownType, packet_op_result_);

  // Call 3 - Multiple value request - DeleteResponse empty
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketError, packet_op_result_);

  // Call 4 - Multiple value request - DeleteResponse doesn't parse
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketParseError, packet_op_result_);

  // Call 5 - Multiple value request - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 6 - Multiple value request - DeleteResponse passes
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, packet_values, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 7 - Single value request - DeleteResponse fails
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, single_value.at(0), MID, PRIVATE, "",
                   functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFailure, packet_op_result_);

  // Call 8 - Single value request - DeleteResponse success
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, single_value.at(0), MID, PRIVATE, "",
                   functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 9 - Single value empty request - DeleteResponse success
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, "", MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 10 - No values - Packet already deleted from net
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);

  // Call 11 - No values - FindValue returns failure
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFindValueFailure, packet_op_result_);

  // Call 12 - No values - FindValue returns success but doesn't populate values
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kDeletePacketFindValueFailure, packet_op_result_);

  // Call 13 - No values - FindValue succeeds
  packet_op_result_ = kGeneralError;
  msm.DeletePacket(hex_packet_name, MID, PRIVATE, "", functor_);
  while (packet_op_result_ == kGeneralError) {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
  ASSERT_EQ(kSuccess, packet_op_result_);
}

}  // namespace maidsafe
