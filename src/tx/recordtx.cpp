// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "recordtx.h"

#include "config/configuration.h"
#include "main.h"

bool CRecordTx::CheckTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    IMPLEMENT_CHECK_TX_FEE;
    IMPLEMENT_CHECK_RECORD_DOMAIN;
    IMPLEMENT_CHECK_RECORD_KEY;
    IMPLEMENT_CHECK_RECORD_VALUE;
    IMPLEMENT_CHECK_TX_REGID_OR_PUBKEY(txUid.type());

    CAccount account;
    if (!cw.accountCache.GetAccount(txUid, account)) {
        return state.DoS(100, ERRORMSG("CRecordTx::CheckTx, read txUid %s account info error", txUid.ToString()),
                         READ_ACCOUNT_FAIL, "bad-read-accountdb");
    }

    CPubKey pubKey = (txUid.type() == typeid(CPubKey) ? txUid.get<CPubKey>() : account.owner_pubkey);
    IMPLEMENT_CHECK_TX_SIGNATURE(pubKey);

    return true;
}

bool CRecordTx::ExecuteTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;
    CAccount account;
    if (!cw.accountCache.GetAccount(txUid, account)) {
        return state.DoS(100, ERRORMSG("CRecordTx::ExecuteTx, read txUid %s account info error", txUid.ToString()),
                         UCOIN_STAKE_FAIL, "bad-read-accountdb");
    }

    if (!GenerateRegID(context, account)) {
        return false;
    }

    if (!account.OperateBalance(fee_symbol, BalanceOpType::SUB_FREE, llFees)) {
        return state.DoS(100,
                         ERRORMSG("CRecordTx::ExecuteTx, insufficient coins in txUid %s account", txUid.ToString()),
                         UPDATE_ACCOUNT_FAIL, "insufficient-coins");
    }

    if (!cw.recordCache.SaveRecord(account.regid, domain, key, value)) {
        return state.DoS(100, ERRORMSG("CRecordTx::ExecuteTx, save record error"), WRITE_RECORD_FAIL,
                         "bad-save-record");
    }

    if (!cw.accountCache.SaveAccount(account)) {
        return state.DoS(100,
                         ERRORMSG("CRecordTx::ExecuteTx, write source addr %s account info error", txUid.ToString()),
                         UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");
    }

    return true;
}

string CRecordTx::ToString(CAccountDBCache &accountCache) {
    return strprintf(
        "txType=%s, hash=%s, ver=%d, txUid=%s, domain=%s, key=%s, value=%s, fee_symbol=%s, llFees=%llu, "
        "valid_height=%d",
        GetTxType(nTxType), GetHash().ToString(), nVersion, txUid.ToString(), HexStr(domain),
        HexStr(key), HexStr(value), fee_symbol, llFees, valid_height);
}

Object CRecordTx::ToJson(const CAccountDBCache &accountCache) const {
    Object result = CBaseTx::ToJson(accountCache);
    result.push_back(Pair("domain", HexStr(domain)));
    result.push_back(Pair("key",    HexStr(key)));
    result.push_back(Pair("value",  HexStr(value)));

    return result;
}
