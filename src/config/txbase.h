// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CONFIG_TXBASE_H
#define CONFIG_TXBASE_H

#include "const.h"

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <cstdint>
#include <tuple>

using namespace std;

static const int32_t INIT_TX_VERSION = 1;

enum TxType : uint8_t {
    NULL_TX = 0,  //!< NULL_TX

    BLOCK_REWARD_TX     = 1,  //!< Miner Block Reward Tx
    ACCOUNT_REGISTER_TX = 2,  //!< Account Registration Tx
    DELEGATE_VOTE_TX    = 3,  //!< Vote Delegate Tx

    COIN_TRANSFER_TX  = 11,  //!< Universal Coin Transfer Tx
    COIN_TRANSFER_MTX = 12,  //!< Multisig Tx
    COIN_STAKE_TX     = 13,  //!< Stake Fund Coin Tx

    CONTRACT_DEPLOY_TX = 21,  //!< universal VM contract deployment
    CONTRACT_INVOKE_TX = 22,  //!< universal VM contract invocation

    ASSET_ISSUE_TX  = 31,  //!< a user issues onchain asset
    ASSET_UPDATE_TX = 32,  //!< a user update onchain asset

    RECORD_TX = 41,  //!< Record Tx
};

struct TxTypeHash {
    size_t operator()(const TxType &type) const noexcept { return std::hash<uint8_t>{}(type); }
};

// Support other issued assets in the future.
static const unordered_set<string> kFeeSymbolSet = {SYMB::SXL};

inline string GetFeeSymbolSetStr() {
    string ret = "";
    for (auto symbol : kFeeSymbolSet) {
        if (ret.empty()) {
            ret = symbol;
        } else {
            ret += "|" + symbol;
        }
    }
    return ret;
}

/**
 * TxTypeKey -> {   TxTypeName, InterimPeriodTxFees(SXL)  }
 *
 * Fees are boosted by COIN=10^8
 */
static const unordered_map<TxType, std::tuple<string, uint64_t>, TxTypeHash> kTxFeeTable = {
/* tx type                                   tx type name               SXL        */
{ NULL_TX,                  std::make_tuple("NULL_TX",                  0           )},

{ BLOCK_REWARD_TX,          std::make_tuple("BLOCK_REWARD_TX",          0           )},

{ ACCOUNT_REGISTER_TX,      std::make_tuple("ACCOUNT_REGISTER_TX",      0           )},

{ DELEGATE_VOTE_TX,         std::make_tuple("DELEGATE_VOTE_TX",         0           )},

{ COIN_TRANSFER_TX,         std::make_tuple("COIN_TRANSFER_TX",         0           )},
{ COIN_TRANSFER_MTX,        std::make_tuple("COIN_TRANSFER_MTX",        0           )},

{ COIN_STAKE_TX,            std::make_tuple("COIN_STAKE_TX",            0           )},

{ ASSET_ISSUE_TX,           std::make_tuple("ASSET_ISSUE_TX",           0           )},
{ ASSET_UPDATE_TX,          std::make_tuple("ASSET_UPDATE_TX",          0           )},

{ CONTRACT_DEPLOY_TX,       std::make_tuple("CONTRACT_DEPLOY_TX",       0           )},
{ CONTRACT_INVOKE_TX,       std::make_tuple("CONTRACT_INVOKE_TX",       0           )},

{ RECORD_TX,                std::make_tuple("RECORD_TX",                0           )},

};

#endif
