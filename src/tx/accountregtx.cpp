// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "accountregtx.h"

#include "commons/serialize.h"
#include "tx.h"
#include "crypto/hash.h"
#include "commons/util.h"
#include "config/version.h"
#include "main.h"
#include "persistence/contractdb.h"
#include "vm/luavm/luavmrunenv.h"
#include "miner/miner.h"

bool CAccountRegisterTx::CheckTx(CTxExecuteContext &context) {
    CValidationState &state = *context.pState;

    IMPLEMENT_CHECK_TX_FEE;

    if (txUid.type() != typeid(CPubKey))
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::CheckTx, userId must be CPubKey"), REJECT_INVALID,
                         "uid-type-error");

    if ((minerUid.type() != typeid(CPubKey)) && (minerUid.type() != typeid(CNullID)))
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::CheckTx, minerId must be CPubKey or CNullID"),
                         REJECT_INVALID, "minerUid-type-error");

    if (!txUid.get<CPubKey>().IsFullyValid())
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::CheckTx, register tx public key is invalid"),
                         REJECT_INVALID, "bad-tx-publickey");

    IMPLEMENT_CHECK_TX_SIGNATURE(txUid.get<CPubKey>());

    return true;
}


bool CAccountRegisterTx::ExecuteTx(CTxExecuteContext &context) {
    CCacheWrapper &cw = *context.pCw; CValidationState &state = *context.pState;
    CAccount account;
    CRegID regId(context.height, context.index);
    CKeyID keyId = txUid.get<CPubKey>().GetKeyId();
    if (!cw.accountCache.GetAccount(txUid, account))
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::ExecuteTx, read source keyId %s account info error",
                        keyId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");

    if (account.HaveOwnerPubKey()) {
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::ExecuteTx, keyId %s duplicate register", keyId.ToString()),
                         UPDATE_ACCOUNT_FAIL, "duplicate-register-account");
    }

    account.regid        = regId;
    account.owner_pubkey = txUid.get<CPubKey>();

    if (!account.OperateBalance(SYMB::SXL, BalanceOpType::SUB_FREE, llFees)) {
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::ExecuteTx, insufficient funds in account, keyid=%s",
                        keyId.ToString()), UPDATE_ACCOUNT_FAIL, "insufficent-funds");
    }

    if (typeid(CPubKey) == minerUid.type()) {
        account.miner_pubkey = minerUid.get<CPubKey>();
        if (!account.miner_pubkey.IsFullyValid()) {
            return state.DoS(100, ERRORMSG("CAccountRegisterTx::ExecuteTx, minerPubKey:%s Is Invalid",
                            account.miner_pubkey.ToString()), UPDATE_ACCOUNT_FAIL, "MinerPKey Is Invalid");
        }
    }

    if (!cw.accountCache.SaveAccount(account))
        return state.DoS(100, ERRORMSG("CAccountRegisterTx::ExecuteTx, write source addr %s account info error",
                        regId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");

    return true;
}

string CAccountRegisterTx::ToString(CAccountDBCache &accountCache) {
    return strprintf("txType=%s, hash=%s, ver=%d, pubkey=%s, llFees=%ld, keyid=%s, valid_height=%d",
                     GetTxType(nTxType), GetHash().ToString(), nVersion, txUid.get<CPubKey>().ToString(), llFees,
                     txUid.get<CPubKey>().GetKeyId().ToAddress(), valid_height);
}

Object CAccountRegisterTx::ToJson(const CAccountDBCache &accountCache) const {
    assert(txUid.type() == typeid(CPubKey));

    Object result = CBaseTx::ToJson(accountCache);
    result.push_back(Pair("pubkey",         txUid.ToString()));
    result.push_back(Pair("miner_pubkey",   minerUid.ToString()));

    return result;
}
