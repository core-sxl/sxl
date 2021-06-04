// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PERSIST_RECEIPTDB_H
#define PERSIST_RECEIPTDB_H

#include "commons/serialize.h"
#include "entities/receipt.h"
#include "dbaccess.h"
#include "dbconf.h"

#include <map>
#include <set>
#include <vector>

using namespace std;

class CTxReceiptDBCache {
public:
    CTxReceiptDBCache() {}
    CTxReceiptDBCache(CDBAccess *pDbAccess) : txReceiptCache(pDbAccess) {}

public:
    bool SetTxReceipts(const TxID &txid, const vector<CReceipt> &receipts);

    bool GetTxReceipts(const TxID &txid, vector<CReceipt> &receipts);

    void Flush();

    uint32_t GetCacheSize() const { return txReceiptCache.GetCacheSize(); }

    void SetBaseViewPtr(CTxReceiptDBCache *pBaseIn) { txReceiptCache.SetBase(&pBaseIn->txReceiptCache); }

    void SetDbOpLogMap(CDBOpLogMap *pDbOpLogMapIn) { txReceiptCache.SetDbOpLogMap(pDbOpLogMapIn); }

    bool UndoData() { return txReceiptCache.UndoData(); }

private:
/*       type               prefixType               key                     value                 variable               */
/*  ----------------   -------------------------   -----------------------  ------------------   ------------------------ */
    /////////// SysParamDB
    // txid -> vector<CReceipt>
    CCompositeKVCache< dbk::TX_RECEIPT,            TxID,                   vector<CReceipt> >     txReceiptCache;
};

#endif // PERSIST_RECEIPTDB_H