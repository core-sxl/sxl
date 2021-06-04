// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ACCOUNT_REGISTER_H
#define ACCOUNT_REGISTER_H

#include "tx.h"

class CAccountRegisterTx : public CBaseTx {
public:
    mutable CUserID minerUid;  // miner pubkey

public:
    CAccountRegisterTx(const CUserID &txUidIn, const CUserID &minerUidIn, const int64_t feesIn,
                       const int32_t validHeight)
        : CBaseTx(ACCOUNT_REGISTER_TX, txUidIn, validHeight, feesIn), minerUid(minerUidIn) {}
    CAccountRegisterTx() : CBaseTx(ACCOUNT_REGISTER_TX) {}
    ~CAccountRegisterTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(minerUid);
        READWRITE(signature);)

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees) << minerUid;

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CAccountRegisterTx>(*this); }
    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif