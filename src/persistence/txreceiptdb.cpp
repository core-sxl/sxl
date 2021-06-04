// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txreceiptdb.h"
#include "config/chainparams.h"

bool CTxReceiptDBCache::SetTxReceipts(const TxID &txid, const vector<CReceipt> &receipts) {
    if (!SysCfg().IsGenReceipt())
        return true;

    return txReceiptCache.SetData(txid, receipts);
}

bool CTxReceiptDBCache::GetTxReceipts(const TxID &txid, vector<CReceipt> &receipts) {
    if (!SysCfg().IsGenReceipt())
        return false;

    return txReceiptCache.GetData(txid, receipts);
}

void CTxReceiptDBCache::Flush() { txReceiptCache.Flush(); }
