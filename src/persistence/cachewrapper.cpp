// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cachewrapper.h"
#include "main.h"


std::shared_ptr<CCacheWrapper>CCacheWrapper::NewCopyFrom(CCacheDBManager* pCdMan) {
    auto pNewCopy = make_shared<CCacheWrapper>();
    pNewCopy->CopyFrom(pCdMan);
    return pNewCopy;
}

CCacheWrapper::CCacheWrapper() {}

CCacheWrapper::CCacheWrapper(CBlockDBCache*  pBlockCacheIn,
                             CAccountDBCache* pAccountCacheIn,
                             CAssetDBCache* pAssetCache,
                             CContractDBCache* pContractCacheIn,
                             CDelegateDBCache* pDelegateCacheIn,
                             CTxReceiptDBCache* pReceiptCacheIn,
                             CRecordDBCache* pRecordCacheIn,
                             CTxMemCache* pTxCacheIn) {
    blockCache.SetBaseViewPtr(pBlockCacheIn);
    accountCache.SetBaseViewPtr(pAccountCacheIn);
    assetCache.SetBaseViewPtr(pAssetCache);
    contractCache.SetBaseViewPtr(pContractCacheIn);
    delegateCache.SetBaseViewPtr(pDelegateCacheIn);
    txReceiptCache.SetBaseViewPtr(pReceiptCacheIn);
    recordCache.SetBaseViewPtr(pRecordCacheIn);

    txCache.SetBaseViewPtr(pTxCacheIn);
}

CCacheWrapper::CCacheWrapper(CCacheWrapper *cwIn) {
    blockCache.SetBaseViewPtr(&cwIn->blockCache);
    accountCache.SetBaseViewPtr(&cwIn->accountCache);
    assetCache.SetBaseViewPtr(&cwIn->assetCache);
    contractCache.SetBaseViewPtr(&cwIn->contractCache);
    delegateCache.SetBaseViewPtr(&cwIn->delegateCache);
    txReceiptCache.SetBaseViewPtr(&cwIn->txReceiptCache);
    recordCache.SetBaseViewPtr(&cwIn->recordCache);

    txCache.SetBaseViewPtr(&cwIn->txCache);
}

CCacheWrapper::CCacheWrapper(CCacheDBManager* pCdMan) {
    blockCache.SetBaseViewPtr(pCdMan->pBlockCache);
    accountCache.SetBaseViewPtr(pCdMan->pAccountCache);
    assetCache.SetBaseViewPtr(pCdMan->pAssetCache);
    contractCache.SetBaseViewPtr(pCdMan->pContractCache);
    delegateCache.SetBaseViewPtr(pCdMan->pDelegateCache);
    txReceiptCache.SetBaseViewPtr(pCdMan->pReceiptCache);
    recordCache.SetBaseViewPtr(pCdMan->pRecordCache);

    txCache.SetBaseViewPtr(pCdMan->pTxCache);
}

void CCacheWrapper::CopyFrom(CCacheDBManager* pCdMan){
    blockCache     = *pCdMan->pBlockCache;
    accountCache   = *pCdMan->pAccountCache;
    assetCache     = *pCdMan->pAssetCache;
    contractCache  = *pCdMan->pContractCache;
    delegateCache  = *pCdMan->pDelegateCache;
    txReceiptCache = *pCdMan->pReceiptCache;
    recordCache    = *pCdMan->pRecordCache;

    txCache = *pCdMan->pTxCache;
}

CCacheWrapper& CCacheWrapper::operator=(CCacheWrapper& other) {
    if (this == &other)
        return *this;

    this->blockCache     = other.blockCache;
    this->accountCache   = other.accountCache;
    this->assetCache     = other.assetCache;
    this->contractCache  = other.contractCache;
    this->delegateCache  = other.delegateCache;
    this->txReceiptCache = other.txReceiptCache;
    this->recordCache    = other.recordCache;
    this->txCache        = other.txCache;

    return *this;
}

void CCacheWrapper::EnableTxUndoLog(const TxID& txid) {
    txUndo.Clear();

    txUndo.SetTxID(txid);
    SetDbOpLogMap(&txUndo.dbOpLogMap);
}

void CCacheWrapper::DisableTxUndoLog() {
    SetDbOpLogMap(nullptr);
}

bool CCacheWrapper::UndoData(CBlockUndo &blockUndo) {
    for (auto it = blockUndo.vtxundo.rbegin(); it != blockUndo.vtxundo.rend(); it++) {
        // TODO: should use foreach(it->dbOpLogMap) to dispatch the DbOpLog to the cache (switch case)
        SetDbOpLogMap(&it->dbOpLogMap);
        bool ret =  blockCache.UndoData() &&
                    accountCache.UndoData() &&
                    assetCache.UndoData() &&
                    contractCache.UndoData() &&
                    delegateCache.UndoData() &&
                    txReceiptCache.UndoData() &&
                    recordCache.UndoData();

        if (!ret) {
            return ERRORMSG("CCacheWrapper::UndoData() : undo data of tx failed! txUndo=%s", txUndo.ToString());
        }
    }
    return true;
}


void CCacheWrapper::Flush() {
    blockCache.Flush();
    accountCache.Flush();
    assetCache.Flush();
    contractCache.Flush();
    delegateCache.Flush();
    txReceiptCache.Flush();
    recordCache.Flush();

    txCache.Flush();
}

void CCacheWrapper::SetDbOpLogMap(CDBOpLogMap *pDbOpLogMap) {
    blockCache.SetDbOpLogMap(pDbOpLogMap);
    accountCache.SetDbOpLogMap(pDbOpLogMap);
    assetCache.SetDbOpLogMap(pDbOpLogMap);
    contractCache.SetDbOpLogMap(pDbOpLogMap);
    delegateCache.SetDbOpLogMap(pDbOpLogMap);
    txReceiptCache.SetDbOpLogMap(pDbOpLogMap);
    recordCache.SetDbOpLogMap(pDbOpLogMap);
}
