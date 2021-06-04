// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TX_COIN_TRANSFER_H
#define TX_COIN_TRANSFER_H

#include "tx.h"

/**
 * Universal Coin Transfer Tx
 *
 */
class CCoinTransferTx: public CBaseTx {
public:
    vector<SingleTransfer> transfers;
    string memo;

public:
    CCoinTransferTx() : CBaseTx(COIN_TRANSFER_TX) {}
    CCoinTransferTx(const CUserID &txUidIn, const CUserID &toUidIn, const int32_t validHeightIn,
                    const TokenSymbol &coinSymbol, const uint64_t coinAmount, const uint64_t feesIn,
                    const string &memoIn)
        : CBaseTx(COIN_TRANSFER_TX, txUidIn, validHeightIn, feesIn),
          transfers({{toUidIn, coinSymbol, coinAmount}}),
          memo(memoIn) {}
    ~CCoinTransferTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(transfers);
        READWRITE(memo);

        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees) << transfers
               << memo;

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CCoinTransferTx>(*this); }
    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif // TX_COIN_TRANSFER_H
