// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mulsigtx.h"

#include "commons/serialize.h"
#include "commons/util.h"
#include "config/version.h"
#include "crypto/hash.h"
#include "main.h"
#include "miner/miner.h"
#include "persistence/contractdb.h"

bool CMulsigTx::CheckTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    IMPLEMENT_CHECK_TX_FEE;
    IMPLEMENT_CHECK_TX_MEMO;

    if (transfers.empty() || transfers.size() > MAX_TRANSFER_SIZE) {
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, transfers is empty or too large count=%d than %d",
            transfers.size(), MAX_TRANSFER_SIZE),
                        REJECT_INVALID, "invalid-transfers");
    }

    for (size_t i = 0; i < transfers.size(); i++) {
        IMPLEMENT_CHECK_TX_REGID_OR_KEYID(transfers[i].to_uid.type());
        auto pSymbolErr = cw.assetCache.CheckTransferCoinSymbol(transfers[i].coin_symbol);
        if (pSymbolErr) {
            return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, transfers[%d], invalid coin_symbol=%s, %s",
                i, transfers[i].coin_symbol, *pSymbolErr), REJECT_INVALID, "invalid-coin-symbol");
        }

        if (!CheckBaseCoinRange(transfers[i].coin_amount))
            return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, transfers[%d], coin_amount=%llu out of valid range",
                i, transfers[i].coin_amount), REJECT_DUST, "invalid-coin-amount");
    }

    uint64_t minFee;
    if (!GetTxMinFee(nTxType, context.height, fee_symbol, minFee)) { assert(false); /* has been check before */ }

    if (llFees < transfers.size() * minFee) {
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, tx fee too small (height: %d, fee symbol: %s, fee: %llu)",
                         context.height, fee_symbol, llFees), REJECT_INVALID, "bad-tx-fee-toosmall");
    }

    if (required < 1 || required > signaturePairs.size()) {
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, required keys invalid"), REJECT_INVALID,
                         "required-keys-invalid");
    }

    if (signaturePairs.size() > MAX_MULSIG_NUMBER) {
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, signature's number out of range"), REJECT_INVALID,
                         "signature-number-out-of-range");
    }

    CAccount account;
    set<CPubKey> pubKeys;
    uint256 sighash = ComputeSignatureHash();
    uint8_t valid   = 0;
    for (const auto &item : signaturePairs) {
        if (!cw.accountCache.GetAccount(item.regid, account))
            return state.DoS(100,
                             ERRORMSG("CMulsigTx::CheckTx, account: %s, read account failed", item.regid.ToString()),
                             REJECT_INVALID, "bad-getaccount");

        if (!item.signature.empty()) {
            if (!CheckSignatureSize(item.signature)) {
                return state.DoS(
                    100, ERRORMSG("CMulsigTx::CheckTx, account: %s, signature size invalid", item.regid.ToString()),
                    REJECT_INVALID, "bad-tx-sig-size");
            }

            if (!VerifySignature(sighash, item.signature, account.owner_pubkey)) {
                return state.DoS(
                    100, ERRORMSG("CMulsigTx::CheckTx, account: %s, VerifySignature failed", item.regid.ToString()),
                    REJECT_INVALID, "bad-signscript-check");
            } else {
                ++valid;
            }
        }

        pubKeys.insert(account.owner_pubkey);
    }

    if (pubKeys.size() != signaturePairs.size()) {
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, duplicated account"), REJECT_INVALID, "duplicated-account");
    }

    if (valid < required) {
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, not enough valid signatures, %u vs %u", valid, required),
                         REJECT_INVALID, "not-enough-valid-signatures");
    }

    CMulsigScript script;
    script.SetMultisig(required, pubKeys);
    keyId = script.GetID();

    CAccount srcAccount;
    if (!cw.accountCache.GetAccount(CUserID(keyId), srcAccount))
        return state.DoS(100, ERRORMSG("CMulsigTx::CheckTx, read multisig account: %s failed", keyId.ToAddress()),
                         READ_ACCOUNT_FAIL, "bad-read-accountdb");

    return true;
}

bool CMulsigTx::ExecuteTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    CAccount srcAccount;
    if (!cw.accountCache.GetAccount(CUserID(keyId), srcAccount)) {
        return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, read source addr account info error"), READ_ACCOUNT_FAIL,
                         "bad-read-accountdb");
    }

    if (!GenerateRegID(context, srcAccount)) {
        return false;
    }

    if (!srcAccount.OperateBalance(fee_symbol, SUB_FREE, llFees)) {
        return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, insufficient coin_amount in %s account",
                        keyId.ToAddress()), UPDATE_ACCOUNT_FAIL, "insufficient-coin_amount");
    }

    vector<CReceipt> receipts;
    for (size_t i = 0; i < transfers.size(); i++) {
        const auto &transfer       = transfers[i];
        uint64_t actualCoinsToSend = transfer.coin_amount;

        if (!srcAccount.OperateBalance(transfer.coin_symbol, SUB_FREE, actualCoinsToSend)) {
            return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, transfers[%d], insufficient coins in %s account",
                            i, keyId.ToAddress()), UPDATE_ACCOUNT_FAIL, "insufficient-coins");
        }

        if (srcAccount.IsMyUid(transfer.to_uid)) {
            if (!srcAccount.OperateBalance(transfer.coin_symbol, ADD_FREE, actualCoinsToSend)) {
                return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, transfers[%d], failed to add coins in toUid %s account",
                    i, transfer.to_uid.ToDebugString()), UPDATE_ACCOUNT_FAIL, "failed-add-coins");
            }
        } else {
            CAccount desAccount;
            if (!cw.accountCache.GetAccount(transfer.to_uid, desAccount)) { // first involved in transacion
                if (transfer.to_uid.is<CKeyID>()) {
                    desAccount = CAccount(transfer.to_uid.get<CKeyID>());
                } else {
                    return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, get account info failed"),
                                    READ_ACCOUNT_FAIL, "bad-read-accountdb");
                }
            }

            if (!desAccount.OperateBalance(transfer.coin_symbol, ADD_FREE, actualCoinsToSend)) {
                return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, transfers[%d], failed to add coins in toUid %s account",
                    i, transfer.to_uid.ToDebugString()), UPDATE_ACCOUNT_FAIL, "failed-add-coins");
            }

            if (!cw.accountCache.SaveAccount(desAccount))
                return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, write dest addr %s account info error",
                    transfer.to_uid.ToDebugString()), UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");
        }

        receipts.emplace_back(keyId, transfer.to_uid, transfer.coin_symbol, actualCoinsToSend, ReceiptCode::TRANSFER_COINS);
    }

    if (!cw.accountCache.SaveAccount(srcAccount))
        return state.DoS(100, ERRORMSG("CMulsigTx::ExecuteTx, write source addr %s account info error",
                        keyId.ToAddress()), UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");

    if (!receipts.empty() && !cw.txReceiptCache.SetTxReceipts(GetHash(), receipts))
        return state.DoS(100, ERRORMSG("CCDPStakeTx::ExecuteTx, set tx receipts failed!! txid=%s",
                        GetHash().ToString()), REJECT_INVALID, "set-tx-receipt-failed");

    return true;
}

bool CMulsigTx::GenerateRegID(CTxExecuteContext &context, CAccount &account) {
    CRegID regId;
    if (context.pCw->accountCache.GetRegId(CUserID(keyId), regId)) {
        // account has regid already, return
        return true;
    }

    // generate a new regid for the account
    account.regid = CRegID(context.height, context.index);
    if (!context.pCw->accountCache.SaveAccount(account))
        return context.pState->DoS(100, ERRORMSG("CMulsigTx::GenerateRegID, save account info error"),
                                   WRITE_ACCOUNT_FAIL, "bad-write-accountdb");

    return true;
}

string CSignaturePair::ToString() const {
    return strprintf("regId=%s, signature=%s", regid.ToString(), HexStr(signature.begin(), signature.end()));
}

Object CSignaturePair::ToJson() const {
    Object obj;
    obj.push_back(Pair("regid",     regid.ToString()));
    obj.push_back(Pair("signature", HexStr(signature.begin(), signature.end())));

    return obj;
}

string CMulsigTx::ToString(CAccountDBCache &accountCache) {
    string signatures;
    signatures += "signatures: ";
    for (const auto &item : signaturePairs) {
        signatures += strprintf("%s, ", item.ToString());
    }

    string transferStr = "";
    for (const auto &transfer : transfers) {
        if (!transferStr.empty()) transferStr += ",";
        transferStr += strprintf("{%s}", transfer.ToString(accountCache));
    }

    return strprintf(
        "txType=%s, hash=%s, ver=%d, required=%d, %s, fee_symbol=%s, llFees=%llu, valid_height=%d, transfers=[%s], "
        "memo=%s",
        GetTxType(nTxType), GetHash().ToString(), nVersion, required, signatures, fee_symbol, llFees, valid_height,
        HexStr(memo), transferStr);
}

Object CMulsigTx::ToJson(const CAccountDBCache &accountCache) const {
    Object result;

    Array signatureArray;
    CAccount account;
    std::set<CPubKey> pubKeys;
    for (const auto &item : signaturePairs) {
        signatureArray.push_back(item.ToJson());
        if (!accountCache.GetAccount(item.regid, account)) {
            LogPrint("ERROR", "CMulsigTx::ToJson, failed to get account info: %s\n", item.regid.ToString());
            continue;
        }
        pubKeys.insert(account.owner_pubkey);
    }
    CMulsigScript script;
    script.SetMultisig(required, pubKeys);
    CKeyID scriptId = script.GetID();

    Array transferArray;
    for (const auto &transfer : transfers) {
        transferArray.push_back(transfer.ToJson(accountCache));
    }


    result.push_back(Pair("txid",           GetHash().GetHex()));
    result.push_back(Pair("tx_type",        GetTxType(nTxType)));
    result.push_back(Pair("version",        nVersion));
    result.push_back(Pair("required_sigs",  required));
    result.push_back(Pair("signatures",     signatureArray));
    result.push_back(Pair("from_addr",      scriptId.ToAddress()));
    result.push_back(Pair("fee_symbol",     fee_symbol));
    result.push_back(Pair("fees",           llFees));
    result.push_back(Pair("valid_height",   valid_height));
    result.push_back(Pair("transfers",      transferArray));
    result.push_back(Pair("memo",           memo));

    return result;
}
