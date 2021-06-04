// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COIN_MINER_H
#define COIN_MINER_H

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <tuple>
#include <vector>

#include "entities/key.h"
#include "commons/uint256.h"
#include "tx/tx.h"

class CBlock;
class CBlockIndex;
class CWallet;
class CBaseTx;
class CAccountDBCache;
class CAccount;

#include <cmath>

using namespace std;

struct TxPriority {
    double priority;
    double feePerKb;
    std::shared_ptr<CBaseTx> baseTx;

    TxPriority(const double priorityIn, const double feePerKbIn, const std::shared_ptr<CBaseTx> &baseTxIn)
        : priority(priorityIn), feePerKb(feePerKbIn), baseTx(baseTxIn) {}

    bool operator<(const TxPriority &other) const {
        if (fabs(this->priority - other.priority) <= 1000) {
            if (fabs(this->feePerKb < other.feePerKb) <= 1e-8) {
                return this->baseTx->GetHash() < other.baseTx->GetHash();
            } else {
                return this->feePerKb < other.feePerKb;
            }
        } else {
            return this->priority < other.priority;
        }
    }
};

/** Run the miner threads */
void GenerateCoinBlock(bool fGenerate, CWallet *pWallet, int32_t nThreads);

bool CreateBlockRewardTx(const int64_t currentTime, const CAccount &delegate, CAccountDBCache &accountCache,
                         CBlock *pBlock);

bool VerifyRewardTx(const CBlock *pBlock, CCacheWrapper &cwIn, bool bNeedRunTx = false);

/** Check mined block */
bool CheckWork(CBlock *pBlock);

/** Get burn element */
uint32_t GetElementForBurn(CBlockIndex *pIndex);

void GetPriorityTx(vector<TxPriority> &vecPriority, int32_t nFuelRate);

void ShuffleDelegates(const int32_t nCurHeight, vector<CRegID> &delegateList);

bool GetCurrentDelegate(const int64_t currentTime, const vector<CRegID> &delegateList, CRegID &delegate);

#endif  // COIN_MINER_H
