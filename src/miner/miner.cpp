// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include <algorithm>
#include <boost/circular_buffer.hpp>

#include "init.h"
#include "main.h"
#include "net.h"
#include "persistence/cachewrapper.h"
#include "persistence/contractdb.h"
#include "persistence/txdb.h"
#include "tx/blockrewardtx.h"
#include "tx/tx.h"
#include "wallet/wallet.h"

extern CWallet *pWalletMain;

// check the time is not exceed the limit time (2s) for packing new block
static bool CheckPackBlockTime(int64_t startMiningMs, int32_t blockHeight) {
    int64_t nowMs         = GetTimeMillis();
    int64_t limitedTimeMs = std::max<int64_t>(1000L, SysCfg().GetBlockInterval() * 1000L - 1000L);
    if (nowMs - startMiningMs > limitedTimeMs) {
        LogPrint("MINER", "%s() : pack block time use up! height=%d, start_ms=%lld, now_ms=%lld, limited_time_ms=%lld\n", __FUNCTION__, blockHeight, startMiningMs, nowMs, limitedTimeMs);
        return false;
    }

    return true;
}

// base on the lastest 50 blocks
uint32_t GetElementForBurn(CBlockIndex *pIndex) {
    if (!pIndex) {
        return INIT_FUEL_RATES;
    }

    int32_t nBlock = SysCfg().GetArg("-blocksizeforburn", DEFAULT_BURN_BLOCK_SIZE);
    if (nBlock * 2 >= (int32_t)pIndex->height - 1) {
        return INIT_FUEL_RATES;
    }

    uint64_t nTotalStep   = 0;
    uint64_t nAverateStep = 0;
    uint32_t newFuelRate  = 0;
    CBlockIndex *pTemp    = pIndex;
    for (int32_t i = 0; i < nBlock; ++i) {
        nTotalStep += pTemp->nFuel / pTemp->nFuelRate * 100;
        pTemp = pTemp->pprev;
    }

    nAverateStep = nTotalStep / nBlock;
    if (nAverateStep < MAX_BLOCK_RUN_STEP * 0.75) {
        newFuelRate = pIndex->nFuelRate * 0.9;
    } else if (nAverateStep > MAX_BLOCK_RUN_STEP * 0.85) {
        newFuelRate = pIndex->nFuelRate * 1.1;
    } else {
        newFuelRate = pIndex->nFuelRate;
    }

    if (newFuelRate < MIN_FUEL_RATES) {
        newFuelRate = MIN_FUEL_RATES;
    }

    LogPrint("fuel", "preFuelRate=%d fuelRate=%d, height=%d\n", pIndex->nFuelRate, newFuelRate, pIndex->height);
    return newFuelRate;
}

// Sort transactions by priority and fee to decide priority orders to process transactions.
void GetPriorityTx(int32_t height, set<TxPriority> &txPriorities, const int32_t nFuelRate) {
    static TokenSymbol feeSymbol;
    static uint64_t fee    = 0;
    static uint32_t txSize = 0;
    static double feePerKb = 0;
    static double priority = 0;

    for (map<uint256, CTxMemPoolEntry>::iterator mi = mempool.memPoolTxs.begin(); mi != mempool.memPoolTxs.end(); ++mi) {
        CBaseTx *pBaseTx = mi->second.GetTransaction().get();
        if (!pBaseTx->IsBlockRewardTx() && pCdMan->pTxCache->HaveTx(pBaseTx->GetHash()) == uint256()) {
            feeSymbol = std::get<0>(mi->second.GetFees());
            fee       = std::get<1>(mi->second.GetFees());
            txSize    = mi->second.GetTxSize();
            feePerKb  = double(fee - pBaseTx->GetFuel(height, nFuelRate)) / txSize * 1000.0;
            priority  = mi->second.GetPriority();

            txPriorities.emplace(TxPriority(priority, feePerKb, mi->second.GetTransaction()));
        }
    }
}

bool GetCurrentDelegate(const int64_t currentTime, const vector<CRegID> &delegates, CRegID &delegate) {
    uint32_t slot  = currentTime / SysCfg().GetBlockInterval();
    uint32_t index = slot % IniCfg().GetTotalDelegateNum();
    delegate       = delegates[index];
    LogPrint("DEBUG", "currentTime=%lld, slot=%d, index=%d, regId=%s\n", currentTime, slot, index, delegate.ToString());

    return true;
}

bool CreateBlockRewardTx(const CAccount &delegate, CAccountDBCache &accountCache, CBlock *pBlock, CKey &minerKey) {
    assert(pBlock->vptx[0]->nTxType == BLOCK_REWARD_TX);
    auto pRewardTx          = (CBlockRewardTx *)pBlock->vptx[0].get();
    pRewardTx->txUid        = delegate.regid;
    pRewardTx->valid_height = pBlock->GetHeight();

    pBlock->SetMerkleRootHash(pBlock->BuildMerkleTree());

    vector<uint8_t> signature;
    if (minerKey.Sign(pBlock->ComputeSignatureHash(), signature)) {
        pBlock->SetSignature(signature);
        return true;
    } else {
        return ERRORMSG("Sign failed");
    }
}

void ShuffleDelegates(const int32_t nCurHeight, vector<CRegID> &delegates) {
    uint32_t totalDelegateNum = IniCfg().GetTotalDelegateNum();
    string seedSource         = strprintf("%u", nCurHeight / totalDelegateNum + (nCurHeight % totalDelegateNum > 0 ? 1 : 0));
    CHashWriter ss(SER_GETHASH, 0);
    ss << seedSource;
    uint256 currentSeed     = ss.GetHash();
    uint64_t newIndexSource = 0;
    for (uint32_t i = 0; i < totalDelegateNum; i++) {
        for (uint32_t x = 0; x < 4 && i < totalDelegateNum; i++, x++) {
            memcpy(&newIndexSource, currentSeed.begin() + (x * 8), 8);
            uint32_t newIndex   = newIndexSource % totalDelegateNum;
            CRegID regId        = delegates[newIndex];
            delegates[newIndex] = delegates[i];
            delegates[i]        = regId;
        }
        ss << currentSeed;
        currentSeed = ss.GetHash();
    }
}

bool VerifyRewardTx(const CBlock *pBlock, CCacheWrapper &cwIn, bool bNeedRunTx) {
    vector<CRegID> delegates;
    if (!cwIn.delegateCache.GetTopDelegateList(delegates))
        return false;

    ShuffleDelegates(pBlock->GetHeight(), delegates);

    CRegID regId;
    if (!GetCurrentDelegate(pBlock->GetTime(), delegates, regId))
        return ERRORMSG("VerifyRewardTx() : failed to acquire current delegate");

    CAccount curDelegate;
    if (!cwIn.accountCache.GetAccount(regId, curDelegate)) {
        string delegatesStr;
        for (const auto &item : delegates) {
            delegatesStr += strprintf("%s, ", item.ToString());
        }

        return ERRORMSG("VerifyRewardTx() : failed to acquire current delegate account(%s), candiate delegates: %s", regId.ToString(), delegatesStr);
    }

    if (pBlock->GetMerkleRootHash() != pBlock->BuildMerkleTree())
        return ERRORMSG("VerifyRewardTx() : wrong merkle root hash");

    auto spCW = std::make_shared<CCacheWrapper>(&cwIn);

    CBlockIndex *pBlockIndex = mapBlockIndex[pBlock->GetPrevBlockHash()];
    if (pBlock->GetHeight() != 1 || pBlock->GetPrevBlockHash() != SysCfg().GetGenesisBlockHash()) {
        CBlock previousBlock;
        if (!ReadBlockFromDisk(pBlockIndex, previousBlock))
            return ERRORMSG("VerifyRewardTx() : read block info failed from disk");

        CAccount prevDelegateAcct;
        if (!spCW->accountCache.GetAccount(previousBlock.vptx[0]->txUid, prevDelegateAcct))
            return ERRORMSG("VerifyRewardTx() : failed to get previous delegate's account, regId=%s", previousBlock.vptx[0]->txUid.ToString());

        if (pBlock->GetBlockTime() - previousBlock.GetBlockTime() < SysCfg().GetBlockInterval()) {
            if (prevDelegateAcct.regid == curDelegate.regid)
                return ERRORMSG("VerifyRewardTx() : one delegate can't produce more than one block at the same slot");
        }
    }

    CAccount account;
    if (spCW->accountCache.GetAccount(pBlock->vptx[0]->txUid, account)) {
        if (curDelegate.regid != account.regid) {
            return ERRORMSG("VerifyRewardTx() : delegate should be (%s) vs what we got (%s)", curDelegate.regid.ToString(), account.regid.ToString());
        }

        const auto &blockHash      = pBlock->ComputeSignatureHash();
        const auto &blockSignature = pBlock->GetSignature();

        if (blockSignature.size() == 0 || blockSignature.size() > MAX_SIGNATURE_SIZE) {
            return ERRORMSG("VerifyRewardTx() : invalid block signature size, hash=%s", blockHash.ToString());
        }

        if (!VerifySignature(blockHash, blockSignature, account.owner_pubkey))
            if (!VerifySignature(blockHash, blockSignature, account.miner_pubkey))
                return ERRORMSG("VerifyRewardTx() : verify signature error");
    } else {
        return ERRORMSG("VerifyRewardTx() : failed to get account info, regId=%s", pBlock->vptx[0]->txUid.ToString());
    }

    if (pBlock->vptx[0]->nVersion != INIT_TX_VERSION)
        return ERRORMSG("VerifyRewardTx() : transaction version %d vs current %d", pBlock->vptx[0]->nVersion, INIT_TX_VERSION);

    if (bNeedRunTx) {
        uint64_t totalFuel    = 0;
        uint64_t totalRunStep = 0;
        for (uint32_t i = 1; i < pBlock->vptx.size(); i++) {
            shared_ptr<CBaseTx> pBaseTx = pBlock->vptx[i];
            if (spCW->txCache.HaveTx(pBaseTx->GetHash()) != uint256())
                return ERRORMSG("VerifyRewardTx() : duplicate transaction, txid=%s", pBaseTx->GetHash().GetHex());

            CValidationState state;
            CTxExecuteContext context(pBlock->GetHeight(), i, pBlock->GetFuelRate(), pBlock->GetTime(), spCW.get(), &state);
            if (!pBaseTx->ExecuteTx(context)) {
                return ERRORMSG("VerifyRewardTx() : failed to execute transaction, txid=%s", pBaseTx->GetHash().GetHex());
            }

            totalRunStep += pBaseTx->nRunStep;
            if (totalRunStep > MAX_BLOCK_RUN_STEP)
                return ERRORMSG("VerifyRewardTx() : block total run steps(%lu) exceed max run step(%lu)", totalRunStep, MAX_BLOCK_RUN_STEP);

            uint32_t fuelFee = pBaseTx->GetFuel(pBlock->GetHeight(), pBlock->GetFuelRate());
            totalFuel += fuelFee;
            LogPrint("fuel", "VerifyRewardTx() : total fuel fee:%d, tx fuel fee:%d runStep:%d fuelRate:%d txid:%s\n", totalFuel, fuelFee, pBaseTx->nRunStep, pBlock->GetFuelRate(),
                     pBaseTx->GetHash().GetHex());
        }

        if (totalFuel != pBlock->GetFuel())
            return ERRORMSG("VerifyRewardTx() : total fuel fee(%lu) mismatch what(%u) in block header", totalFuel, pBlock->GetFuel());
    }

    return true;
}

static bool CreateNewBlock(int64_t startMiningMs, CCacheWrapper &cwIn, std::unique_ptr<CBlock> &pBlock) {
    pBlock->vptx.push_back(std::make_shared<CBlockRewardTx>());

    // Largest block you're willing to create:
    uint32_t nBlockMaxSize = SysCfg().GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max<uint32_t>(1000, std::min<uint32_t>((MAX_BLOCK_SIZE - 1000), nBlockMaxSize));

    // Collect memory pool transactions into the block
    {
        LOCK2(cs_main, mempool.cs);

        CBlockIndex *pIndexPrev = chainActive.Tip();
        uint32_t blockTime      = pBlock->GetTime();
        int32_t height          = pIndexPrev->height + 1;
        int32_t index           = 0;
        uint32_t fuelRate       = GetElementForBurn(pIndexPrev);
        uint64_t totalBlockSize = ::GetSerializeSize(*pBlock, SER_NETWORK, PROTOCOL_VERSION);
        uint64_t totalRunStep   = 0;
        uint64_t totalFees      = 0;
        uint64_t totalFuel      = 0;
        uint64_t totalRewards   = 0;

        // Calculate && sort transactions from memory pool.
        set<TxPriority> txPriorities;
        GetPriorityTx(height, txPriorities, fuelRate);

        LogPrint("MINER", "CreateNewBlock() : got %lu transaction(s) sorted by priority rules\n", txPriorities.size());

        // Collect transactions into the block.
        for (auto itor = txPriorities.rbegin(); itor != txPriorities.rend(); ++itor) {
            if (!CheckPackBlockTime(startMiningMs, height)) {
                LogPrint("MINER", "%s() : no time left to pack more tx, ignore! height=%d, start_ms=%lld, tx_count=%u\n", __FUNCTION__, height, startMiningMs, pBlock->vptx.size());
                break;
            }

            CBaseTx *pBaseTx = itor->baseTx.get();

            uint32_t txSize = pBaseTx->GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION);
            if (totalBlockSize + txSize >= nBlockMaxSize) {
                LogPrint("MINER", "CreateNewBlock() : exceed max block size, txid: %s\n", pBaseTx->GetHash().GetHex());
                continue;
            }

            auto spCW = std::make_shared<CCacheWrapper>(&cwIn);

            try {
                CValidationState state;
                pBaseTx->nFuelRate = fuelRate;

                LogPrint("MINER", "CreateNewBlock() : begin to pack transaction: %s\n", pBaseTx->ToString(spCW->accountCache));

                CTxExecuteContext context(height, index + 1, fuelRate, blockTime, spCW.get(), &state);
                if (!pBaseTx->CheckTx(context) || !pBaseTx->ExecuteTx(context)) {
                    LogPrint("MINER", "CreateNewBlock() : failed to pack transaction: %s\n", pBaseTx->ToString(spCW->accountCache));
                    continue;
                }

                // Run step limits
                if (totalRunStep + pBaseTx->nRunStep >= MAX_BLOCK_RUN_STEP) {
                    LogPrint("MINER", "CreateNewBlock() : exceed max block run steps, txid: %s\n", pBaseTx->GetHash().GetHex());
                    continue;
                }
            } catch (std::exception &e) {
                LogPrint("ERROR", "CreateNewBlock() : unexpected exception: %s\n", e.what());

                continue;
            }

            spCW->Flush();

            auto fuel        = pBaseTx->GetFuel(height, fuelRate);
            auto fees_symbol = std::get<0>(pBaseTx->GetFees());
            assert(fees_symbol == SYMB::SXL);
            auto fees = std::get<1>(pBaseTx->GetFees());

            totalBlockSize += txSize;
            totalRunStep += pBaseTx->nRunStep;
            totalFuel += fuel;
            totalFees += fees;
            assert(fees >= fuel);
            totalRewards += (fees - fuel);

            ++index;

            pBlock->vptx.push_back(itor->baseTx);

            LogPrint("fuel", "miner total fuel fee:%d, tx fuel fee:%d, fuel:%d, fuelRate:%d, txid:%s\n", totalFuel, pBaseTx->GetFuel(height, fuelRate), pBaseTx->nRunStep, fuelRate,
                     pBaseTx->GetHash().GetHex());
        }

        ((CBlockRewardTx *)pBlock->vptx[0].get())->coin_amount = totalRewards;

        // Fill in header
        pBlock->SetPrevBlockHash(pIndexPrev->GetBlockHash());
        pBlock->SetHeight(height);
        pBlock->SetFuel(totalFuel);
        pBlock->SetFuelRate(fuelRate);

        LogPrint("INFO", "CreateNewBlock() : height=%d, tx=%d, totalBlockSize=%llu\n", height, index + 1, totalBlockSize);
    }

    return true;
}

bool CheckWork(CBlock *pBlock) {
    // Print block information
    pBlock->Print();

    if (pBlock->GetPrevBlockHash() != chainActive.Tip()->GetBlockHash())
        return ERRORMSG("CheckWork() : generated block is stale");

    // Process this block the same as if we received it from another node
    CValidationState state;
    if (!ProcessBlock(state, nullptr, pBlock))
        return ERRORMSG("CheckWork() : failed to process block");

    return true;
}

static bool GetMiner(int64_t startMiningMs, const int32_t blockHeight, CAccount &minerAccount, CKey &minerKey) {
    vector<CRegID> delegates;
    {
        LOCK(cs_main);

        if (!pCdMan->pDelegateCache->GetTopDelegateList(delegates)) {
            LogPrint("MINER", "GetMiner() : fail to get top delegates! height=%d, time_ms=%lld\n", blockHeight, startMiningMs);
            return false;
        }
    }

    uint16_t index = 0;
    for (auto &delegate : delegates) LogPrint("shuffle", "before shuffle: index=%d, regId=%s\n", index++, delegate.ToString());

    ShuffleDelegates(blockHeight, delegates);

    index = 0;
    for (auto &delegate : delegates) LogPrint("shuffle", "after shuffle: index=%d, regId=%s\n", index++, delegate.ToString());

    CRegID minerRegId;
    GetCurrentDelegate(MillisToSecond(startMiningMs), delegates, minerRegId);

    {
        LOCK(cs_main);

        if (!pCdMan->pAccountCache->GetAccount(minerRegId, minerAccount)) {
            LogPrint("MINER", "GetMiner() : fail to get miner account! height=%d, time_ms=%lld, regid=%s\n", blockHeight, startMiningMs, minerRegId.ToString());
            return false;
        }
    }
    bool isMinerKey = false;
    {
        LOCK(pWalletMain->cs_wallet);

        if (minerAccount.miner_pubkey.IsValid() && pWalletMain->GetKey(minerAccount.keyid, minerKey, true)) {
            isMinerKey = true;
        } else if (!pWalletMain->GetKey(minerAccount.keyid, minerKey)) {
            LogPrint("MINER",
                     "GetMiner() : [ignore] miner key does not exist in wallet! height=%d, time_ms=%lld, "
                     "regid=%s, addr=%s\n",
                     blockHeight, startMiningMs, minerRegId.ToString(), minerAccount.keyid.ToAddress());
            return false;
        }
    }
    LogPrint("INFO", "GetMiner(), succeed to get the duty miner! height=%d, time_ms=%lld, regid=%s, addr=%s, use_miner_key=%d\n", blockHeight, startMiningMs, minerRegId.ToString(),
             minerAccount.keyid.ToAddress(), isMinerKey);
    return true;
}

static bool MineBlock(int64_t startMiningMs, CBlockIndex *pPrevIndex, const CAccount &minerAccount, CKey &minerKey) {
    int64_t lastTime    = 0;
    bool success        = false;
    int32_t blockHeight = 0;
    std::unique_ptr<CBlock> pBlock(new CBlock());
    if (!pBlock.get())
        throw runtime_error("MineBlock() : failed to create new block");

    {
        LOCK(cs_main);
        CBlockIndex *pTipIndex = chainActive.Tip();
        if (pPrevIndex != pTipIndex) {
            LogPrint("MINER", "%s() : active chain tip changed when mining! pre_block=%d:%s, tip_block=%d:%s\n", __FUNCTION__, pPrevIndex->height, pPrevIndex->GetBlockHash().ToString(),
                     pTipIndex->height, pTipIndex->GetBlockHash().ToString());
            return false;
        }

        blockHeight = pPrevIndex->height + 1;

        if (!CheckPackBlockTime(startMiningMs, blockHeight)) {
            LogPrint("MINER", "%s() : no time left to pack block! height=%d, start_ms=%lld, miner_regid=%s\n", __FUNCTION__, blockHeight, startMiningMs, minerAccount.regid.ToString());
            return false;
        }

        lastTime  = GetTimeMillis();
        auto spCW = std::make_shared<CCacheWrapper>(pCdMan);

        pBlock->SetTime(MillisToSecond(startMiningMs));  // set block time first

        success = CreateNewBlock(startMiningMs, *spCW, pBlock);

        if (!success) {
            LogPrint("MINER",
                     "MineBlock() : fail to create new block! height=%d, regid=%s, "
                     "used_time_ms=%lld\n",
                     blockHeight, minerAccount.regid.ToString(), GetTimeMillis() - lastTime);
            return false;
        }
        LogPrint("MINER",
                 "MineBlock() : succeed to create new block! height=%d, regid=%s, tx_count=%u, "
                 "used_time_ms=%lld\n",
                 blockHeight, minerAccount.regid.ToString(), pBlock->vptx.size(), GetTimeMillis() - lastTime);

        lastTime = GetTimeMillis();
        success  = CreateBlockRewardTx(minerAccount, spCW->accountCache, pBlock.get(), minerKey);
        if (!success) {
            LogPrint("MINER",
                     "MineBlock() : fail to create block reward tx! height=%d, regid=%s, "
                     "used_time_ms=%lld\n",
                     blockHeight, minerAccount.regid.ToString(), GetTimeMillis() - lastTime);
            return false;
        }
        LogPrint("MINER",
                 "MineBlock() : succeed to create block reward tx! height=%d, regid=%s, reward_txid=%s, "
                 "used_time_ms=%lld\n",
                 blockHeight, minerAccount.regid.ToString(), pBlock->vptx[0]->GetHash().ToString(), GetTimeMillis() - lastTime);

        lastTime = GetTimeMillis();
        success  = CheckWork(pBlock.get());
        if (!success) {
            LogPrint("MINER",
                     "MineBlock(), fail to check work for new block, height=%d, regid=%s, "
                     "used_time_ms=%lld\n",
                     blockHeight, minerAccount.regid.ToString(), GetTimeMillis() - lastTime);
            return false;
        }
        LogPrint("MINER",
                 "MineBlock(), succeed to check work of new block, height=%d, regid=%s, hash=%s, "
                 "used_time_ms=%lld\n",
                 blockHeight, minerAccount.regid.ToString(), pBlock->GetHash().ToString(), GetTimeMillis() - lastTime);
    }

    LogPrint("INFO",
             "%s(), succeed to mine a new block, height=%d, regid=%s, hash=%s, "
             "used_time_ms=%lld\n",
             __FUNCTION__, blockHeight, minerAccount.regid.ToString(), pBlock->GetHash().ToString(), GetTimeMillis() - startMiningMs);
    return true;
}

void static CoinMiner(CWallet *pWallet, int32_t targetHeight) {
    LogPrint("INFO", "CoinMiner() : started\n");

    RenameThread("Coin-miner");

    auto HaveMinerKey = [&]() {
        LOCK2(cs_main, pWalletMain->cs_wallet);

        set<CKeyID> setMineKey;
        setMineKey.clear();
        pWalletMain->GetKeys(setMineKey, true);
        return !setMineKey.empty();
    };

    if (!HaveMinerKey()) {
        LogPrint("ERROR", "CoinMiner() : terminated due to lack of miner key\n");
        return;
    }

    auto GetCurrHeight = [&]() {
        LOCK(cs_main);
        return chainActive.Height();
    };

    targetHeight += GetCurrHeight();
    bool needSleep       = false;
    int64_t nextSlotTime = 0;

    try {
        while (true) {
            boost::this_thread::interruption_point();

            if (SysCfg().NetworkID() != REGTEST_NET && !SysCfg().GetBoolArg("-genblockforce", false)) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                while (vNodes.empty() || (chainActive.Tip() && chainActive.Height() > 1 && GetAdjustedTime() - chainActive.Tip()->nTime > 60 * 60)) {
                    MilliSleep(1000);
                    needSleep = false;
                }
            }

            if (needSleep) {
                MilliSleep(100);
            }

            CBlockIndex *pIndexPrev;
            {
                LOCK(cs_main);
                pIndexPrev = chainActive.Tip();
            }

            int32_t blockHeight   = pIndexPrev->height + 1;
            int64_t blockInterval = SysCfg().GetBlockInterval();
            int64_t startMiningMs = GetTimeMillis();
            int64_t curMiningTime = MillisToSecond(startMiningMs);
            int64_t curSlotTime   = std::max<int64_t>(nextSlotTime, pIndexPrev->GetBlockTime() + blockInterval);
            if (curMiningTime < curSlotTime) {
                needSleep = true;
                continue;
            }

            CAccount minerAccount;
            CKey minerKey;
            if (!GetMiner(startMiningMs, blockHeight, minerAccount, minerKey)) {
                needSleep = true;
                // miner key not exist in my wallet, skip to next slot time
                nextSlotTime = std::max<int64_t>(curSlotTime + blockInterval, curMiningTime - curMiningTime % blockInterval);
                continue;
            }

            if (!MineBlock(startMiningMs, pIndexPrev, minerAccount, minerKey)) {
                continue;
            }

            if (SysCfg().NetworkID() != MAIN_NET && targetHeight <= GetCurrHeight())
                throw boost::thread_interrupted();
        }
    } catch (...) {
        LogPrint("INFO", "CoinMiner() : terminated\n");
        throw;
    }
}

void GenerateCoinBlock(bool fGenerate, CWallet *pWallet, int32_t targetHeight) {
    static boost::thread_group *minerThreads = nullptr;

    if (minerThreads != nullptr) {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = nullptr;
    }

    if (!fGenerate)
        return;

    // In mainnet, coin miner should generate blocks continuously regardless of target height.
    if (SysCfg().NetworkID() != MAIN_NET && targetHeight <= 0) {
        LogPrint("ERROR", "GenerateCoinBlock() : target height <=0 (%d)", targetHeight);
        return;
    }

    minerThreads = new boost::thread_group();
    minerThreads->create_thread(boost::bind(&CoinMiner, pWallet, targetHeight));
}
