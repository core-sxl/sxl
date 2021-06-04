// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TX_COIN_STAKE_H
#define TX_COIN_STAKE_H

#include "tx.h"

class CCoinStakeTx: public CBaseTx {
private:
    BalanceOpType stake_type;
    TokenSymbol coin_symbol;
    uint64_t coin_amount;

public:
    CCoinStakeTx() : CBaseTx(COIN_STAKE_TX), stake_type(BalanceOpType::NULL_OP), coin_amount(0) {}
    CCoinStakeTx(const CUserID &txUidIn, const int32_t validHeightIn, const uint64_t feesIn,
                 const BalanceOpType stakeType, const TokenSymbol &coinSymbol, const uint64_t coinAmount)
        : CBaseTx(COIN_STAKE_TX, txUidIn, validHeightIn, feesIn),
          stake_type(stakeType),
          coin_symbol(coinSymbol),
          coin_amount(coinAmount) {}
    ~CCoinStakeTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE((uint8_t &)stake_type);
        READWRITE(coin_symbol);
        READWRITE(VARINT(coin_amount));

        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees)
               << (uint8_t)stake_type << coin_symbol << VARINT(coin_amount);

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CCoinStakeTx>(*this); }
    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif
