// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "contracttx.h"

#include "entities/vote.h"
#include "commons/serialize.h"
#include "crypto/hash.h"
#include "main.h"
#include "miner/miner.h"
#include "persistence/contractdb.h"
#include "persistence/txdb.h"
#include "commons/util.h"
#include "config/version.h"
#include "vm/luavm/luavmrunenv.h"

// get and check fuel limit
static bool GetFuelLimit(CBaseTx &tx, CTxExecuteContext &context, uint64_t &fuelLimit) {
    uint64_t fuelRate = context.fuel_rate;
    if (fuelRate == 0)
        return context.pState->DoS(100, ERRORMSG("GetFuelLimit, fuelRate cannot be 0"), REJECT_INVALID, "invalid-fuel-rate");

    uint64_t minFee;
    if (!GetTxMinFee(tx.nTxType, context.height, tx.fee_symbol, minFee))
        return context.pState->DoS(100, ERRORMSG("GetFuelLimit, get minFee failed"), REJECT_INVALID, "get-min-fee-failed");

    assert(tx.llFees >= minFee);

    uint64_t reservedFeesForMiner = minFee * CONTRACT_CALL_RESERVED_FEES_RATIO / 100;
    uint64_t reservedFeesForGas   = tx.llFees - reservedFeesForMiner;

    fuelLimit = std::min<uint64_t>((reservedFeesForGas / fuelRate) * 100, MAX_BLOCK_RUN_STEP);

    if (fuelLimit == 0) {
        return context.pState->DoS(100, ERRORMSG("GetFuelLimit, fuelLimit == 0"), REJECT_INVALID,
                                   "fuel-limit-equals-zero");
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// class CContractDeployTx

bool CContractDeployTx::CheckTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    IMPLEMENT_CHECK_TX_FEE;
    IMPLEMENT_CHECK_TX_REGID(txUid.type());

    if (contract.vm_type != VMType::LUA_VM) {
        return state.DoS(100, ERRORMSG("CContractDeployTx::CheckTx, support LuaVM only"), REJECT_INVALID,
                         "vm-type-error");
    }

    if (!contract.IsValid()) {
        return state.DoS(100, ERRORMSG("CContractDeployTx::CheckTx, contract is invalid"),
                         REJECT_INVALID, "vmscript-invalid");
    }

    uint64_t llFuel = GetFuel(context.height, context.fuel_rate);
    if (llFees < llFuel) {
        return state.DoS(100, ERRORMSG("CContractDeployTx::CheckTx, fee too small to cover fuel: %llu < %llu",
                        llFees, llFuel), REJECT_INVALID, "fee-too-small-to-cover-fuel");
    }

    CAccount account;
    if (!cw.accountCache.GetAccount(txUid, account)) {
        return state.DoS(100, ERRORMSG("CContractDeployTx::CheckTx, get account failed"),
                         REJECT_INVALID, "bad-getaccount");
    }

    if (!account.HaveOwnerPubKey()) {
        return state.DoS(100, ERRORMSG("CContractDeployTx::CheckTx, account unregistered"),
            REJECT_INVALID, "bad-account-unregistered");
    }

    IMPLEMENT_CHECK_TX_SIGNATURE(account.owner_pubkey);

    return true;
}

bool CContractDeployTx::ExecuteTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    CAccount account;
    if (!cw.accountCache.GetAccount(txUid, account))
        return state.DoS(100, ERRORMSG("CContractDeployTx::ExecuteTx, read regist addr %s account info error", txUid.ToString()),
                         UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");

    CAccount accountLog(account);
    if (!account.OperateBalance(fee_symbol, BalanceOpType::SUB_FREE, llFees))
        return state.DoS(100, ERRORMSG("CContractDeployTx::ExecuteTx, operate account failed ,regId=%s", txUid.ToString()),
                         UPDATE_ACCOUNT_FAIL, "operate-account-failed");

    if (!cw.accountCache.SetAccount(CUserID(account.keyid), account))
        return state.DoS(100, ERRORMSG("CContractDeployTx::ExecuteTx, save account info error"), UPDATE_ACCOUNT_FAIL,
                         "bad-save-accountdb");

    // create script account
    CAccount contractAccount;
    CRegID contractRegId(context.height, context.index);
    CKeyID keyId           = Hash160(contractRegId.GetRegIdRaw());
    contractAccount.keyid  = keyId;
    contractAccount.regid  = contractRegId;
    contractAccount.nickid = CNickID();

    // save new script content
    if (!cw.contractCache.SaveContract(contractRegId, contract))
        return state.DoS(100, ERRORMSG("CContractDeployTx::ExecuteTx, save code for contract id %s error",
                         contractRegId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-save-scriptdb");

    if (!cw.accountCache.SaveAccount(contractAccount))
        return state.DoS(100, ERRORMSG("CContractDeployTx::ExecuteTx, create new account script id %s script info error",
                         contractRegId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-save-scriptdb");

    nRunStep = contract.GetContractSize();

    return true;
}

uint64_t CContractDeployTx::GetFuel(int32_t height, uint32_t nFuelRate) {
    uint64_t minFee = 0;
    if (!GetTxMinFee(nTxType, height, fee_symbol, minFee)) {
        LogPrint("ERROR", "CContractDeployTx::GetFuel(), get min_fee failed! fee_symbol=%s\n", fee_symbol);
        throw runtime_error("CContractDeployTx::GetFuel(), get min_fee failed");
    }

    return std::max<uint64_t>(((nRunStep / 100.0f) * nFuelRate), minFee);
}

string CContractDeployTx::ToString(CAccountDBCache &accountCache) {
    CKeyID keyId;
    accountCache.GetKeyId(txUid, keyId);

    return strprintf("txType=%s, hash=%s, ver=%d, txUid=%s, addr=%s, fee_symbol=%s, llFees=%llu, valid_height=%d",
                     GetTxType(nTxType), GetHash().ToString(), nVersion, txUid.ToString(), keyId.ToAddress(),
                     fee_symbol, llFees, valid_height);
}

Object CContractDeployTx::ToJson(const CAccountDBCache &accountCache) const {
    Object result = CBaseTx::ToJson(accountCache);

    result.push_back(Pair("vm_type",    contract.vm_type));
    result.push_back(Pair("upgradable", contract.upgradable));
    result.push_back(Pair("code",       HexStr(contract.code)));
    result.push_back(Pair("memo",       contract.memo));
    result.push_back(Pair("abi",        contract.abi));

    return result;
}

///////////////////////////////////////////////////////////////////////////////
// class CContractInvokeTx

bool CContractInvokeTx::CheckTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    IMPLEMENT_CHECK_TX_FEE;
    IMPLEMENT_CHECK_TX_ARGUMENTS;
    IMPLEMENT_CHECK_TX_REGID_OR_PUBKEY(txUid.type());
    IMPLEMENT_CHECK_TX_APPID(app_uid.type());

    if ((txUid.type() == typeid(CPubKey)) && !txUid.get<CPubKey>().IsFullyValid())
        return state.DoS(100, ERRORMSG("CContractInvokeTx::CheckTx, public key is invalid"), REJECT_INVALID,
                         "bad-publickey");

    CAccount srcAccount;
    if (!cw.accountCache.GetAccount(txUid, srcAccount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::CheckTx, read account failed, txUid=%s",
                        txUid.ToDebugString()), REJECT_INVALID, "bad-getaccount");

    auto pSymbolErr = cw.assetCache.CheckTransferCoinSymbol(coin_symbol);
    if (pSymbolErr)
        return state.DoS(100, ERRORMSG("CContractInvokeTx::CheckTx, invalid coin_symbol=%s, %s", coin_symbol, *pSymbolErr),
                         REJECT_INVALID, "invalid-coin-symbol");

    CUniversalContract contract;
    if (!cw.contractCache.GetContract(app_uid.get<CRegID>(), contract))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::CheckTx, read script failed, regId=%s",
                         app_uid.get<CRegID>().ToString()), REJECT_INVALID, "bad-read-script");

    CPubKey pubKey = (txUid.type() == typeid(CPubKey) ? txUid.get<CPubKey>() : srcAccount.owner_pubkey);
    IMPLEMENT_CHECK_TX_SIGNATURE(pubKey);

    return true;
}

bool CContractInvokeTx::ExecuteTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    uint64_t fuelLimit;
    if (!GetFuelLimit(*this, context, fuelLimit))
        return false;

    vector<CReceipt> receipts;

    CAccount srcAccount;
    if (!cw.accountCache.GetAccount(txUid, srcAccount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, read source addr account info error"),
                         READ_ACCOUNT_FAIL, "bad-read-accountdb");

    if (!GenerateRegID(context, srcAccount))
        return false;

    if (!srcAccount.OperateBalance(fee_symbol, BalanceOpType::SUB_FREE, llFees))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, accounts hash insufficient funds"),
                         UPDATE_ACCOUNT_FAIL, "operate-minus-account-failed");

    if (!srcAccount.OperateBalance(coin_symbol, BalanceOpType::SUB_FREE, coin_amount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, accounts hash insufficient funds"),
                         UPDATE_ACCOUNT_FAIL, "operate-minus-account-failed");

    if (!cw.accountCache.SetAccount(CUserID(srcAccount.keyid), srcAccount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, save account info error"),
                         WRITE_ACCOUNT_FAIL, "bad-write-accountdb");

    CAccount desAccount;
    if (!cw.accountCache.GetAccount(app_uid, desAccount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, get account info failed by regid:%s",
                        app_uid.get<CRegID>().ToString()), READ_ACCOUNT_FAIL, "bad-read-accountdb");

    if (!desAccount.OperateBalance(coin_symbol, BalanceOpType::ADD_FREE, coin_amount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, operate accounts error"),
                        UPDATE_ACCOUNT_FAIL, "operate-add-account-failed");

    if (!cw.accountCache.SetAccount(app_uid, desAccount))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, save account error, kyeId=%s",
                        desAccount.keyid.ToString()), UPDATE_ACCOUNT_FAIL, "bad-save-account");

    CUniversalContract contract;
    if (!cw.contractCache.GetContract(app_uid.get<CRegID>(), contract))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, read script failed, regId=%s",
                        app_uid.get<CRegID>().ToString()), READ_ACCOUNT_FAIL, "bad-read-script");

    CLuaVMRunEnv vmRunEnv;

    CLuaVMContext luaContext;
    luaContext.p_cw              = &cw;
    luaContext.height            = context.height;
    luaContext.block_time        = context.block_time;
    luaContext.p_base_tx         = this;
    luaContext.fuel_limit        = fuelLimit;
    luaContext.transfer_symbol   = coin_symbol;
    luaContext.transfer_amount   = coin_amount;
    luaContext.p_tx_user_account = &srcAccount;
    luaContext.p_app_account     = &desAccount;
    luaContext.p_contract        = &contract;
    luaContext.p_arguments       = &arguments;

    int64_t llTime = GetTimeMillis();
    auto pExecErr  = vmRunEnv.ExecuteContract(&luaContext, nRunStep);
    if (pExecErr)
        return state.DoS(
            100, ERRORMSG("CContractInvokeTx::ExecuteTx, txid=%s run script error:%s", GetHash().GetHex(), *pExecErr),
            UPDATE_ACCOUNT_FAIL, "run-script-error: " + *pExecErr);

    receipts.insert(receipts.end(), vmRunEnv.GetReceipts().begin(), vmRunEnv.GetReceipts().end());

    LogPrint("vm", "execute contract elapse: %lld, txid=%s\n", GetTimeMillis() - llTime, GetHash().GetHex());

    if (!cw.txReceiptCache.SetTxReceipts(GetHash(), receipts))
        return state.DoS(100, ERRORMSG("CContractInvokeTx::ExecuteTx, set tx receipts failed!! txid=%s",
                        GetHash().ToString()), REJECT_INVALID, "set-tx-receipt-failed");

    return true;
}

string CContractInvokeTx::ToString(CAccountDBCache &accountCache) {
    return strprintf(
        "txType=%s, hash=%s, ver=%d, txUid=%s, app_uid=%s, coin_symbol=%s, coin_amount=%llu, fee_symbol=%s, "
        "llFees=%llu, arguments=%s, valid_height=%d",
        GetTxType(nTxType), GetHash().ToString(), nVersion, txUid.ToString(), app_uid.ToString(), coin_symbol,
        coin_amount, fee_symbol, llFees, HexStr(arguments), valid_height);
}

Object CContractInvokeTx::ToJson(const CAccountDBCache &accountCache) const {
    Object result = CBaseTx::ToJson(accountCache);

    CKeyID desKeyId;
    accountCache.GetKeyId(app_uid, desKeyId);
    result.push_back(Pair("to_addr",        desKeyId.ToAddress()));
    result.push_back(Pair("to_uid",         app_uid.ToString()));
    result.push_back(Pair("coin_symbol",    coin_symbol));
    result.push_back(Pair("coin_amount",    coin_amount));
    result.push_back(Pair("arguments",      HexStr(arguments)));

    return result;
}
