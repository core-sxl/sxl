// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef ENTITIES_RECEIPT_H
#define ENTITIES_RECEIPT_H

#include "config/txbase.h"
#include "crypto/hash.h"
#include "entities/asset.h"
#include "entities/id.h"
#include "commons/json/json_spirit_utils.h"

static CUserID nullId;

//         ReceiptCode                   CodeValue         memo
//       -----------------              ----------  ----------------------------
#define RECEIPT_CODE_LIST(DEFINE) \
    /**** reward */ \
    DEFINE(BLOCK_REWORD_TO_MINER,               101, "block reward to miner") \
    /**** register */ \
    DEFINE(ACCOUNT_REGISTER,                    201, "account register fee") \
    /**** delegate */ \
    DEFINE(DELEGATE_ADD_VOTE,                   301, "delegate add votes") \
    DEFINE(DELEGATE_SUB_VOTE,                   302, "delegate sub votes") \
    DEFINE(DELEGATE_VOTE_INTEREST,              303, "delegate vote interest") \
    /**** transfer */ \
    DEFINE(TRANSFER_COINS,                      401, "actual transferred coins") \
    /**** stake */ \
    DEFINE(STAKE_COINS,                         501, "actual staked coins") \
    DEFINE(UNSTAKE_COINS,                       502, "actual unstaked coins") \
    /**** asset */ \
    DEFINE(ASSET_ISSUED_FEE_TO_RISERVE,         601, "asset issued fee to risk riserve") \
    DEFINE(ASSET_UPDATED_FEE_TO_RISERVE,        602, "asset updated fee to risk riserve") \
    DEFINE(ASSET_ISSUED_FEE_TO_MINER,           603, "asset issued fee to miner") \
    DEFINE(ASSET_UPDATED_FEE_TO_MINER,          604, "asset updated fee to miner") \
    /**** contract */ \
    DEFINE(CONTRACT_FUEL_TO_RISK_RISERVE,       701, "contract fuel to risk riserve") \
    DEFINE(CONTRACT_TOKEN_OPERATE_ADD,          702, "operate add token of contract user account") \
    DEFINE(CONTRACT_TOKEN_OPERATE_SUB,          703, "operate sub token of contract user account") \
    DEFINE(CONTRACT_TOKEN_OPERATE_TAG_ADD,      704, "operate add token tag of contract user account") \
    DEFINE(CONTRACT_TOKEN_OPERATE_TAG_SUB,      705, "operate sub token tag of contract user account") \
    DEFINE(CONTRACT_ACCOUNT_OPERATE_ADD,        706, "operate add bcoins of account by contract") \
    DEFINE(CONTRACT_ACCOUNT_OPERATE_SUB,        707, "operate sub bcoins of account by contract") \
    DEFINE(CONTRACT_ACCOUNT_TRANSFER_ASSET,     708, "transfer account asset by contract")

#define DEFINE_RECEIPT_CODE_TYPE(enumType, code, enumName) enumType = code,
enum ReceiptCode: uint16_t {
    RECEIPT_CODE_LIST(DEFINE_RECEIPT_CODE_TYPE)
};

#define DEFINE_RECEIPT_CODE_NAMES(enumType, code, enumName) { ReceiptCode::enumType, enumName },
static const EnumTypeMap<ReceiptCode, string> RECEIPT_CODE_NAMES = {
    RECEIPT_CODE_LIST(DEFINE_RECEIPT_CODE_NAMES)
};

inline const string& GetReceiptCodeName(ReceiptCode code) {
    const auto it = RECEIPT_CODE_NAMES.find(code);
    if (it != RECEIPT_CODE_NAMES.end())
        return it->second;
    return EMPTY_STRING;
}

class CReceipt {
public:
    CUserID     from_uid;
    CUserID     to_uid;
    TokenSymbol coin_symbol;
    uint64_t    coin_amount;
    ReceiptCode code;

public:
    CReceipt() {}

    CReceipt(const CUserID &fromUid, const CUserID &toUid, const TokenSymbol &coinSymbol, const uint64_t coinAmount,
             ReceiptCode codeIn)
        : from_uid(fromUid), to_uid(toUid), coin_symbol(coinSymbol), coin_amount(coinAmount), code(codeIn) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(from_uid);
        READWRITE(to_uid);
        READWRITE(coin_symbol);
        READWRITE(VARINT(coin_amount));
        READWRITE_CONVERT(uint16_t, code);
    )
};

#endif  // ENTITIES_RECEIPT_H