// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PERSIST_CACHEWRAPPER_H
#define PERSIST_CACHEWRAPPER_H

#include "accountdb.h"
#include "assetdb.h"
#include "blockdb.h"
#include "commons/uint256.h"
#include "contractdb.h"
#include "delegatedb.h"
#include "txdb.h"
#include "txreceiptdb.h"
#include "recorddb.h"

class CCacheDBManager;
class CBlockUndo;
class CCacheWrapper {
public:
    CBlockDBCache       blockCache;
    CAccountDBCache     accountCache;
    CAssetDBCache       assetCache;
    CContractDBCache    contractCache;
    CDelegateDBCache    delegateCache;
    CTxReceiptDBCache   txReceiptCache;
    CRecordDBCache      recordCache;

    CTxMemCache         txCache;

    CTxUndo             txUndo;
public:
    static std::shared_ptr<CCacheWrapper> NewCopyFrom(CCacheDBManager* pCdMan);
public:
    CCacheWrapper();

    CCacheWrapper(CBlockDBCache*  pBlockCacheIn,
                  CAccountDBCache* pAccountCacheIn,
                  CAssetDBCache* pAssetCache,
                  CContractDBCache* pContractCacheIn,
                  CDelegateDBCache* pDelegateCacheIn,
                  CTxReceiptDBCache* pReceiptCacheIn,
                  CRecordDBCache* pRecordCacheIn,
                  CTxMemCache *pTxCacheIn);
    CCacheWrapper(CCacheWrapper* cwIn);
    CCacheWrapper(CCacheDBManager* pCdMan);

    CCacheWrapper& operator=(CCacheWrapper& other);

    void CopyFrom(CCacheDBManager* pCdMan);

    void EnableTxUndoLog(const TxID& txidIn);
    void DisableTxUndoLog();
    const CTxUndo& GetTxUndo() const { return txUndo; }
    bool UndoData(CBlockUndo &blockUndo);
    void Flush();

private:
    CCacheWrapper(const CCacheWrapper&) = delete;
    CCacheWrapper& operator=(const CCacheWrapper&) = delete;

    void SetDbOpLogMap(CDBOpLogMap *pDbOpLogMap);
};

#endif //PERSIST_CACHEWRAPPER_H