// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include "chainparams.h"
#include "commons/arith_uint256.h"
#include "commons/uint256.h"
#include "commons/util.h"
#include "version.h"

#include <map>
#include <memory>
#include <vector>

using namespace std;

class CBlockIndex;
class uint256;
class G_CONFIG_TABLE;

const G_CONFIG_TABLE& IniCfg();

class G_CONFIG_TABLE {
public:
    string GetCoinName() const { return COIN_NAME; }
    const string GetInitPubKey(const NET_TYPE type) const;
    uint256 GetGenesisBlockHash(const NET_TYPE type) const;
    const vector<string> GetDelegatePubKey(const NET_TYPE type) const;
    const uint256 GetMerkleRootHash() const;
    vector<uint32_t> GetSeedNodeIP() const;
    uint8_t* GetMagicNumber(const NET_TYPE type) const;
    vector<uint8_t> GetAddressPrefix(const NET_TYPE type, const Base58Type BaseType) const;
    const string GetPubkeyAddressPrefix(const NET_TYPE type) const;
    uint32_t GetDefaultPort(const NET_TYPE type) const;
    uint32_t GetRPCPort(const NET_TYPE type) const;
    uint32_t GetStartTimeInit(const NET_TYPE type) const;
    uint32_t GetTotalDelegateNum() const;
    uint32_t GetMaxVoteCandidateNum() const;
    uint64_t GetInitialCoin() const { return InitialCoin; };

private:
    static string COIN_NAME; /* basecoin name */

    /* initial public key */
    static string initPubKey[3];

    /* delegate public key */
    static vector<string> delegatePubKey[3];

    /* gensis block hash */
    static string genesisBlockHash[3];

    /* merkle root hash */
    static string MerkleRootHash;

    /* Peer IP seeds */
    static vector<uint32_t> pnSeed;

    /* Network Magic Number */
    static uint8_t MessageMagicNumber[3][MESSAGE_START_SIZE];

    /* Address Prefix */
    static vector<uint8_t> AddrPrefix[2][MAX_BASE58_TYPES];

    static string PubkeyAddressPrefix[2];

    /* P2P Port */
    static uint32_t nP2PPort[3];

    /* RPC Port */
    static uint32_t nRPCPort[2];

    /* Start Time */
    static uint32_t StartTime[3];

    /* Initial Coin */
    static uint64_t InitialCoin;

    /* Default Miner Fee */
    static uint64_t DefaultFee;

    /* Total Delegate Number */
    static uint32_t TotalDelegateNum;

    /* Max Number of Delegate Candidate to Vote for by a single account */
    static uint32_t MaxVoteCandidateNum;
};

inline uint32_t GetYearBlockCount() {
    return 365 /* days/year */ * 24 /* hours/day */ * 60 * 60 / SysCfg().GetBlockInterval();
}

inline uint32_t GetJumpHeightBySubsidy(const uint8_t targetSubsidyRate) {
    assert(targetSubsidyRate >= FIXED_SUBSIDY_RATE && targetSubsidyRate <= INITIAL_SUBSIDY_RATE);

    static map<uint8_t, uint32_t> subsidyRate2BlockHeight;
    static bool initialized = false;

    if (!initialized) {
        uint32_t jumpHeight         = 0;
        uint32_t adjustPeriodHeight = SysCfg().NetworkID() == MAIN_NET ? GetYearBlockCount() : ADJUST_SUBSIDY_RATE_PERIOD;

        for (uint8_t subsidyRate = INITIAL_SUBSIDY_RATE; subsidyRate >= FIXED_SUBSIDY_RATE; --subsidyRate) {
            subsidyRate2BlockHeight[subsidyRate] = jumpHeight;
            jumpHeight += adjustPeriodHeight;
        }

        initialized = true;
        assert(subsidyRate2BlockHeight.size() == 5);
    }

    // for (const auto& item : subsidyRate2BlockHeight) {
    //     LogPrint("DEBUG", "subsidyRate -> blockHeight: %d -> %u\n", item.first, item.second);
    // }

    return subsidyRate2BlockHeight.at(targetSubsidyRate);
}

inline uint8_t GetSubsidyRate(const int32_t currBlockHeight) {
    for (uint8_t subsidyRate = FIXED_SUBSIDY_RATE; subsidyRate <= INITIAL_SUBSIDY_RATE; ++subsidyRate) {
        if ((uint32_t)currBlockHeight >= GetJumpHeightBySubsidy(subsidyRate))
            return subsidyRate;
    }

    assert(false && "failed to acquire subsidy rate");
    return 0;
}

static const int32_t INIT_BLOCK_VERSION = 1;

/* No amount larger than this (in savl) is valid */
static const int64_t BASECOIN_MAX_MONEY = IniCfg().GetInitialCoin() * COIN;  // 12 million

inline int64_t GetBaseCoinMaxMoney() { return BASECOIN_MAX_MONEY; }
inline bool CheckBaseCoinRange(const int64_t amount) { return (amount >= 0 && amount <= BASECOIN_MAX_MONEY); }

#endif /* CONFIGURATION_H_ */
