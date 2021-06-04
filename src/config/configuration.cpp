// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "configuration.h"

#include "commons/arith_uint256.h"
#include "commons/uint256.h"
#include "main.h"
#include "commons/util.h"

#include <stdint.h>
#include <boost/assign/list_of.hpp>  // for 'map_list_of()'
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <memory>
#include <vector>

using namespace std;

const G_CONFIG_TABLE& IniCfg() {
    static G_CONFIG_TABLE* psCfg = nullptr;
    if (psCfg == nullptr) {
        psCfg = new G_CONFIG_TABLE();
    }
    assert(psCfg != nullptr);

    return *psCfg;
}

uint256 G_CONFIG_TABLE::GetGenesisBlockHash(const NET_TYPE type) const {
    assert(type >= 0 && type < 3);
    return uint256S(genesisBlockHash[type]);
}

const string G_CONFIG_TABLE::GetInitPubKey(const NET_TYPE type) const {
    assert(type >= 0 && type < 3);
    return initPubKey[type];
}

const vector<string> G_CONFIG_TABLE::GetDelegatePubKey(const NET_TYPE type) const {
    assert(type >= 0 && type < 3);
    return delegatePubKey[type];
}

const uint256 G_CONFIG_TABLE::GetMerkleRootHash() const { return (uint256S((MerkleRootHash))); }

vector<uint32_t> G_CONFIG_TABLE::GetSeedNodeIP() const { return pnSeed; }

uint8_t* G_CONFIG_TABLE::GetMagicNumber(const NET_TYPE type) const {
    assert(type >= 0 && type < 3);
    return MessageMagicNumber[type];
}

vector<uint8_t> G_CONFIG_TABLE::GetAddressPrefix(const NET_TYPE type, const Base58Type BaseType) const {
    assert(type >= 0 && type < 2);
    return AddrPrefix[type][BaseType];
}

const string G_CONFIG_TABLE::GetPubkeyAddressPrefix(const NET_TYPE type) const {
    return PubkeyAddressPrefix[type];
}

uint32_t G_CONFIG_TABLE::GetDefaultPort(const NET_TYPE type) const {
    assert(type >= 0 && type < 2);
    return nP2PPort[type];
}

uint32_t G_CONFIG_TABLE::GetRPCPort(const NET_TYPE type) const {
    assert(type >=0 && type < 2);
    return nRPCPort[type];
}

uint32_t G_CONFIG_TABLE::GetStartTimeInit(const NET_TYPE type) const {
    assert(type >= 0 && type < 3);
    return StartTime[type];
}

uint32_t G_CONFIG_TABLE::GetTotalDelegateNum() const { return TotalDelegateNum; }

uint32_t G_CONFIG_TABLE::GetMaxVoteCandidateNum() const { return MaxVoteCandidateNum; }

string G_CONFIG_TABLE::COIN_NAME = "SXL";

string G_CONFIG_TABLE::initPubKey[3] = {
    "0282bc50ba8d423fa90dca7ddf9d5953ac6fd4eb3903dda160e4ed3e466ed8be93",  // mainnet
    "02e67ff7c179773a98811043c12f56c3b3177c403908eb3b3e602bc6883026b384",  // testnet
    "03986936d27211dc30b947676ab6117008ea554d62336b7ef8277b2e973300e21e"   // regtest
};

// Initial batch of delegates' public keys
vector<string> G_CONFIG_TABLE::delegatePubKey[3] {
    {   //mainnet
        "02946ec73cdd88cb701c451fa2d9bc9d088b8446ade706c5fd9d9eb14a733718ab",
        "03692ee430e2516a1bf61b2b2ecff06884e67b4f1f22a4b0e787e0ca19a2d9f7c9",
        "02249a2d496606ce553c9dba6073074bc5ae4cccac62b4e5f29f7e896928fccf65",
        "023eaabec4fa2a02425d6b46a61a1e17d974091629d764bd80f458ac6b3b1203c3",
        "0364ff9e973301e3ea08f741ba38ac3fdfc779abcba6fcae49a8216a15e0c65fdc",
        "02979c0fbcdc4f637c9ec96dc2924a94430449642015710f68a57a41e8e9672f9e",
        "03d5bc2d18f121a53d7e15d31f7b36511e681454d988b89f82e807ed1e7e8bf313",
        "03c4c84502eb0866935043c58c5c8ffc02e8b40bc02aca3dd45fb16a97bfb8f1b0",
        "026389fd120a2fe0f1e50d96b8ec81ca976ea798047d9862507f43f7579f36cfef",
        "030f3f09d06764561cc9311ba2069f22190235b2dd95aa2213aa8aaef27f5b5f23",
        "03338f2fc7dd90909b6805079682f1db5ad0e38bd5f902b1b9909ef4e42b375f0b"
    }, { //testnet
        "02557b9a988ef43b1d046b3c0b851a2f8e281fb47cca02ab8d621948ba2606aaa0",
        "039582e4661d827b9efb6176e5b15dd0a85b5e4bb92dca5a57b88300f6b57b1cb2",
        "0289e325e1cc24b7641a3f18c08e41ef8ba2bc25f0f66e4f622406011c3dbddd56",
        "03074de70aa14df50073faaa112abbaa8b74bfd36a547622d99c844bff7e92919a",
        "02e9c1acdd81df35456247faa5bb1b1b6f1d90f14300967143ce81fc0c7bcf5cd9",
        "02b799cc41126216e0b9d1a5993c347a3dcdcf210a9c45fa02e7075329e57eee79",
        "028f7a297990ea8fe6bceaee53cf3e318f3fbb1b2c40c430520821bb510b0a8278",
        "03fe17de157f5c85bd1334a1107fe1c844ee1767b612c0eb086ebfe9946b81a826",
        "0358b36fcd578f1520be4db4c92e6e02195b626db069369bf8acdbf259db53c525",
        "02ea48428464612b45a0d4169dc5ffe9d482e3cc9e9211be4bde91e4526aa3cde2",
        "03709abfd4b65d47fec7de95c417732f5ca176f3cb7c9cc5e32fd8af334bfd38f9"
    }, { //regtest
        "03beef5987cb50dceab0242a660cdab2e0e8911d42e2b2fe77eb35b4520d9092c3",
        "037c0cb7f5a57a79606a23aabfecacbaf44c2e92ad7b7b7ceb8db98e7de1edd61b",
        "031e79514e215efbe024ed522166fe3e7ea42d0c3485a9f32a7d19c13012a74e56",
        "0327d9bbd28adaaea8026e265bdbdcbe07711e7c4db419e9070cc0229c784fa673",
        "0382379a7d8abc3064bb9110ecc91bd4b7e6ba4688d9644aacf8fcade8c939fa83",
        "023821819fd8a44d79eefbf192e74ca7c081570cd7b71ec39c207c220735d2b5b0",
        "03328bb884dacfc2e84c6f161e0816d9cddd55e2fbd528f72493e203ac5488a56f",
        "027736a868f2b2f11bfbe4cb5669b6a1002ead395e3ee88cbf3282b616e6844419",
        "02a9db4f18f1e805944b777c3d149098c327ed1f63358352c0ca73d8ad1f9f084e",
        "025065a70477c4069f4800312baa59ce41f9f5066fe575c41939fa435471758a3c",
        "03c1c57f51f8c0a75e9e62098cfb51379cd8636a9aabcf98f90143cce20ae73271"
    }
};

// Gensis Block Hash
string G_CONFIG_TABLE::genesisBlockHash[3] = {
    "d551775c3b8629df1976b97641e1f9d614db1a2ae996dd2314edfaef89ef1c57",   //mainnet
    "fd08823044362d0838ab398aa1e74613e812c0aa4c186eed2408593cbf67d60f",   //testnet
    "e7911409865a0d5aa511cb19e9ec96120c1ffabc60469588fc1c1a337dc3f354"};  //regtest

// Merkle Root Hash
string G_CONFIG_TABLE::MerkleRootHash = "3d25abb224999f17584c24fde043b70e20b4351cdfee3c18f3f0cd4e2c906205";

// IP Address
vector<uint32_t> G_CONFIG_TABLE::pnSeed = {};

// Network Magic No.
uint8_t G_CONFIG_TABLE::MessageMagicNumber[3][MESSAGE_START_SIZE] {
    {0xff, 0x42, 0x1d, 0x1a},  //mainnet
    {0xfd, 0x7d, 0x5c, 0xe1},  //testnet
    {0xfe, 0xfa, 0xd3, 0xc6}   //regtest
};

// Address Prefix
vector<uint8_t> G_CONFIG_TABLE::AddrPrefix[2][MAX_BASE58_TYPES] = {
    { {}, {51}, {153}, {0x4c, 0x1d, 0x3d, 0x5f}, {0x4c, 0x23, 0x3f, 0x4b}, {0} },
    { {}, {88}, {210}, {0x7d, 0x57, 0x3a, 0x2c}, {0x7d, 0x5c, 0x5A, 0x26}, {0} }
};

string G_CONFIG_TABLE::PubkeyAddressPrefix[2] = { "SXL" /*mainnet*/, "sxl" /*testnet*/ };

// Default P2P Port
uint32_t G_CONFIG_TABLE::nP2PPort[3] = {18888 /*mainnet*/, 18889 /*testnet*/};

// Default RPC Port
uint32_t G_CONFIG_TABLE::nRPCPort[2] = {20000 /*mainnet*/, 20001 /*testnet*/};

// Blockchain Start Time: 2020-04-24 06:06:06
uint32_t G_CONFIG_TABLE::StartTime[3] = {1587679566 /*mainnet*/, 1587679566 /*testnet*/, 1587679566 /*regtest*/};

// Initial Coin
uint64_t G_CONFIG_TABLE::InitialCoin = INITIAL_BASE_COIN_SUPPLY;

// Default Miner Fee
uint64_t G_CONFIG_TABLE::DefaultFee = 15;

// Total Delegate Number
uint32_t G_CONFIG_TABLE::TotalDelegateNum = 11;
// Max Number of Delegate Candidate to Vote for by a single account
uint32_t G_CONFIG_TABLE::MaxVoteCandidateNum = 22;
