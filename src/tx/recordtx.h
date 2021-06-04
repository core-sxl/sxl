// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TX_RECORD_H
#define TX_RECORD_H

#include "tx.h"

class CRecordTx: public CBaseTx {
private:
    string domain;
    string key;
    string value;

public:
    CRecordTx() : CBaseTx(RECORD_TX) {}
    CRecordTx(const CUserID &txUidIn, const int32_t validHeightIn, const uint64_t feesIn,
                 const string &domainIn, const string &keyIn, const string &valueIn)
        : CBaseTx(RECORD_TX, txUidIn, validHeightIn, feesIn),
          domain(domainIn),
          key(keyIn),
          value(valueIn) {}
    ~CRecordTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(domain);
        READWRITE(key);
        READWRITE(value);

        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees)
               << domain << key << value;

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CRecordTx>(*this); }
    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif
