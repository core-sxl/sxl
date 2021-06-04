// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COIN_BASETX_H
#define COIN_BASETX_H

#include "commons/serialize.h"
#include "commons/uint256.h"
#include "entities/account.h"
#include "entities/asset.h"
#include "entities/id.h"
#include "persistence/contractdb.h"
#include "persistence/blockdb.h"
#include "config/configuration.h"
#include "config/txbase.h"
#include "config/scoin.h"

#include "commons/json/json_spirit_utils.h"
#include "commons/json/json_spirit_value.h"

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

class CCacheWrapper;
class CValidationState;

string GetTxType(const TxType txType);
bool GetTxMinFee(const TxType nTxType, int32_t height, const TokenSymbol &symbol, uint64_t &feeOut);

class CTxExecuteContext {
public:
    int32_t height;
    int32_t index;
    uint32_t fuel_rate;
    uint32_t block_time;
    CCacheWrapper *pCw;
    CValidationState *pState;

    CTxExecuteContext()
        : height(0),
          index(0),
          fuel_rate(0),
          block_time(0),
          pCw(nullptr),
          pState(nullptr) {}

    CTxExecuteContext(const int32_t heightIn, const int32_t indexIn, const uint32_t fuelRateIn,
                      const uint32_t blockTimeIn, CCacheWrapper *pCwIn, CValidationState *pStateIn)
        : height(heightIn),
          index(indexIn),
          fuel_rate(fuelRateIn),
          block_time(blockTimeIn),
          pCw(pCwIn),
          pState(pStateIn) {}
};

class CBaseTx {
public:
    static const int32_t CURRENT_VERSION = INIT_TX_VERSION;

    int32_t nVersion;
    TxType nTxType;
    mutable CUserID txUid;
    int32_t valid_height;
    TokenSymbol fee_symbol;  // fee symbol, default is SXL
    uint64_t llFees;
    UnsignedCharArray signature;

    uint64_t nRunStep;     //!< only in memory
    int32_t nFuelRate;     //!< only in memory
    mutable TxID sigHash;  //!< only in memory

public:
    CBaseTx(int32_t nVersionIn, TxType nTxTypeIn, CUserID txUidIn, int32_t nValidHeightIn, uint64_t llFeesIn) :
        nVersion(nVersionIn), nTxType(nTxTypeIn), txUid(txUidIn), valid_height(nValidHeightIn),
        fee_symbol(SYMB::SXL), llFees(llFeesIn), nRunStep(0), nFuelRate(0) {}

    CBaseTx(TxType nTxTypeIn, CUserID txUidIn, int32_t nValidHeightIn, uint64_t llFeesIn) :
        nVersion(CURRENT_VERSION), nTxType(nTxTypeIn), txUid(txUidIn), valid_height(nValidHeightIn),
        fee_symbol(SYMB::SXL), llFees(llFeesIn), nRunStep(0), nFuelRate(0) {}

    CBaseTx(TxType nTxTypeIn, CUserID txUidIn, int32_t nValidHeightIn) :
        nVersion(CURRENT_VERSION), nTxType(nTxTypeIn), txUid(txUidIn), valid_height(nValidHeightIn),
        fee_symbol(SYMB::SXL), llFees(0), nRunStep(0), nFuelRate(0) {}

    CBaseTx(int32_t nVersionIn, TxType nTxTypeIn) :
        nVersion(nVersionIn), nTxType(nTxTypeIn), valid_height(0), fee_symbol(SYMB::SXL), llFees(0), nRunStep(0),
        nFuelRate(0) {}

    CBaseTx(TxType nTxTypeIn) :
        nVersion(CURRENT_VERSION), nTxType(nTxTypeIn), valid_height(0), fee_symbol(SYMB::SXL), llFees(0), nRunStep(0),
        nFuelRate(0) {}

    virtual ~CBaseTx() {}

    virtual std::pair<TokenSymbol, uint64_t> GetFees() const { return std::make_pair(fee_symbol, llFees); }
    virtual TxID GetHash() const { return ComputeSignatureHash(); }
    virtual uint32_t GetSerializeSize(int32_t nType, int32_t nVersion) const { return 0; }

    virtual uint64_t GetFuel(int32_t height, uint32_t nFuelRate);
    virtual double GetPriority() const {
        return TRANSACTION_PRIORITY_CEILING / GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION);
    }
    virtual TxID ComputeSignatureHash(bool recalculate = false) const = 0;
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const           = 0;
    virtual string ToString(CAccountDBCache &accountCache)            = 0;
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context)   = 0;
    virtual bool ExecuteTx(CTxExecuteContext &context) = 0;

    bool IsValidHeight(int32_t nCurHeight, int32_t nTxCacheHeight) const;

    // If the sender has no regid before, geneate a regid for the sender.
    bool GenerateRegID(CTxExecuteContext &context, CAccount &account);

    bool IsBlockRewardTx() { return nTxType == BLOCK_REWARD_TX; }

protected:
    bool CheckTxFeeSufficient(const TokenSymbol &feeSymbol, const uint64_t llFees, const int32_t height) const;
    bool CheckSignatureSize(const vector<unsigned char> &signature) const;
    bool CheckCoinRange(const TokenSymbol &symbol, const int64_t amount) const;
};

/**################################ Universal Coin Transfer ########################################**/

struct SingleTransfer {
    CUserID to_uid;
    TokenSymbol coin_symbol = SYMB::SXL;
    uint64_t coin_amount    = 0;

    SingleTransfer() {}

    SingleTransfer(const CUserID &toUidIn, const TokenSymbol &coinSymbol, const uint64_t coinAmount)
        : to_uid(toUidIn), coin_symbol(coinSymbol), coin_amount(coinAmount) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(to_uid);
        READWRITE(coin_symbol);
        READWRITE(VARINT(coin_amount));
    )
    string ToString(const CAccountDBCache &accountCache) const;

    Object ToJson(const CAccountDBCache &accountCache) const;
};

#define IMPLEMENT_CHECK_TX_MEMO                                                                    \
    if (memo.size() > MAX_COMMON_TX_MEMO_SIZE) {                                                   \
        return state.DoS(100, ERRORMSG("%s, memo's size too large", __FUNCTION__), REJECT_INVALID, \
                         "memo-size-toolarge");                                                    \
    }

#define IMPLEMENT_CHECK_TX_ARGUMENTS                                                                    \
    if (arguments.size() > MAX_CONTRACT_ARGUMENT_SIZE) {                                                \
        return state.DoS(100, ERRORMSG("%s, arguments's size too large", __FUNCTION__), REJECT_INVALID, \
                         "arguments-size-toolarge");                                                    \
    }

#define IMPLEMENT_CHECK_TX_FEE                                                                                 \
    if (!CheckBaseCoinRange(llFees)) {                                                                         \
        return state.DoS(100, ERRORMSG("%s, tx fee out of range", __FUNCTION__), REJECT_INVALID,               \
                         "bad-tx-fee-toolarge");                                                               \
    }                                                                                                          \
    if (!kFeeSymbolSet.count(fee_symbol)) {                                                                    \
        return state.DoS(100,                                                                                  \
                         ERRORMSG("%s, not support fee symbol=%s, only supports:%s", __FUNCTION__, fee_symbol, \
                                  GetFeeSymbolSetStr()),                                                       \
                         REJECT_INVALID, "bad-tx-fee-symbol");                                                 \
    }                                                                                                          \
    if (!CheckTxFeeSufficient(fee_symbol, llFees, context.height)) {                                           \
        return state.DoS(100,                                                                                  \
                         ERRORMSG("%s, tx fee too small(height: %d, fee symbol: %s, fee: %llu)", __FUNCTION__, \
                                  context.height, fee_symbol, llFees),                                         \
                         REJECT_INVALID, "bad-tx-fee-toosmall");                                               \
    }

#define IMPLEMENT_CHECK_TX_REGID(txUidType)                                                            \
    if (txUidType != typeid(CRegID)) {                                                                 \
        return state.DoS(100, ERRORMSG("%s, txUid must be CRegID", __FUNCTION__), REJECT_INVALID,      \
            "txUid-type-error");                                                                       \
    }

#define IMPLEMENT_CHECK_TX_APPID(appUidType)                                                       \
    if (appUidType != typeid(CRegID)) {                                                            \
        return state.DoS(100, ERRORMSG("%s, appUid must be CRegID", __FUNCTION__), REJECT_INVALID, \
                         "appUid-type-error");                                                     \
    }

#define IMPLEMENT_CHECK_TX_REGID_OR_PUBKEY(txUidType)                                                        \
    if ((txUidType != typeid(CRegID)) && (txUidType != typeid(CPubKey))) {                                   \
        return state.DoS(100, ERRORMSG("%s, txUid must be CRegID or CPubKey", __FUNCTION__), REJECT_INVALID, \
                         "txUid-type-error");                                                                \
    }

#define IMPLEMENT_CHECK_TX_CANDIDATE_REGID(candidateUidType)                                             \
    if (candidateUidType != typeid(CRegID)) {                                                            \
        return state.DoS(100, ERRORMSG("%s, candidateUid must be CRegID", __FUNCTION__), REJECT_INVALID, \
                         "candidateUid-type-error");                                                     \
    }

#define IMPLEMENT_CHECK_TX_REGID_OR_KEYID(toUidType)                                                        \
    if ((toUidType != typeid(CRegID)) && (toUidType != typeid(CKeyID))) {                                   \
        return state.DoS(100, ERRORMSG("%s, toUid must be CRegID or CKeyID", __FUNCTION__), REJECT_INVALID, \
                         "toUid-type-error");                                                               \
    }

#define IMPLEMENT_CHECK_TX_SIGNATURE(signatureVerifyPubKey)                                                          \
    if (!CheckSignatureSize(signature)) {                                                                            \
        return state.DoS(100, ERRORMSG("%s, tx signature size invalid", __FUNCTION__), REJECT_INVALID,               \
                         "bad-tx-sig-size");                                                                         \
    }                                                                                                                \
    uint256 sighash = ComputeSignatureHash();                                                                        \
    if (!VerifySignature(sighash, signature, signatureVerifyPubKey)) {                                               \
        return state.DoS(100, ERRORMSG("%s, tx signature error", __FUNCTION__), REJECT_INVALID, "bad-tx-signature"); \
    }

#define IMPLEMENT_CHECK_RECORD_DOMAIN                                                                \
    if (domain.size() > MAX_RECORD_DOMAIN_SIZE) {                                                    \
        return state.DoS(100, ERRORMSG("%s, domain's size too large", __FUNCTION__), REJECT_INVALID, \
                         "domain-size-toolarge");                                                    \
    }

#define IMPLEMENT_CHECK_RECORD_KEY                                                                                 \
    if (key.empty()) {                                                                                             \
        return state.DoS(100, ERRORMSG("%s, key should not be empty", __FUNCTION__), REJECT_INVALID, "key-empty"); \
    }                                                                                                              \
    if (key.size() > MAX_RECORD_KEY_SIZE) {                                                                        \
        return state.DoS(100, ERRORMSG("%s, key's size too large", __FUNCTION__), REJECT_INVALID,                  \
                         "key-size-toolarge");                                                                     \
    }

#define IMPLEMENT_CHECK_RECORD_VALUE                                                                \
    if (value.size() > MAX_RECORD_VALUE_SIZE) {                                                     \
        return state.DoS(100, ERRORMSG("%s, value's size too large", __FUNCTION__), REJECT_INVALID, \
                         "value-size-toolarge");                                                    \
    }

#endif //COIN_BASETX_H
