// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef TX_BLOCK_REWARD_H
#define TX_BLOCK_REWARD_H

#include "tx.h"

class CBlockRewardTx : public CBaseTx {
public:
    uint64_t coin_amount;

public:
    CBlockRewardTx() : CBaseTx(BLOCK_REWARD_TX), coin_amount(0) {}
    CBlockRewardTx(const CUserID &txUid, const uint64_t coinAmount, const int32_t validHeight)
        : CBaseTx(BLOCK_REWARD_TX, txUid, validHeight), coin_amount(coinAmount) {}
    ~CBlockRewardTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);

        READWRITE(VARINT(coin_amount));
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(coin_amount);

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CBlockRewardTx>(*this); }

    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif // TX_BLOCK_REWARD_H
