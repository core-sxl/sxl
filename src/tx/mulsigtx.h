// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COIN_MULSIGTX_H
#define COIN_MULSIGTX_H

#include "tx.h"

class CSignaturePair {
public:
    CRegID regid;                 //!< regid only
    UnsignedCharArray signature;  //!< signature

    IMPLEMENT_SERIALIZE(
        READWRITE(regid);
        READWRITE(signature);)

public:
    CSignaturePair(const CSignaturePair &signaturePair) {
        regid     = signaturePair.regid;
        signature = signaturePair.signature;
    }

    CSignaturePair(const CRegID &regIdIn, const UnsignedCharArray &signatureIn) {
        regid     = regIdIn;
        signature = signatureIn;
    }

    CSignaturePair() {}

    string ToString() const;
    Object ToJson() const;
};

class CMulsigTx : public CBaseTx {
public:
    vector<SingleTransfer> transfers;       //!< transfer pair
    string memo;                            //!< memo
    uint8_t required;                       //!< number of required keys
    vector<CSignaturePair> signaturePairs;  //!< signature pair

    CKeyID keyId;  //!< only in memory

public:
    CMulsigTx() : CBaseTx(COIN_TRANSFER_MTX) {}
    CMulsigTx(const CUserID &toUidIn, const int32_t validHeightIn, const TokenSymbol &coinSymbolIn,
              const uint64_t coinAmountIn, const uint64_t feesIn, const string &memoIn, const uint8_t requiredIn,
              const vector<CSignaturePair> &signaturePairsIn)
        : CBaseTx(COIN_TRANSFER_MTX, CNullID(), validHeightIn, feesIn),
          transfers({{toUidIn, coinSymbolIn, coinAmountIn}}),
          memo(memoIn),
          required(requiredIn),
          signaturePairs(signaturePairsIn) {}
    ~CMulsigTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(VARINT(llFees));

        READWRITE(transfers);
        READWRITE(memo);
        READWRITE((uint8_t&)required);

        READWRITE(signaturePairs);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << VARINT(llFees) << transfers << memo
               << uint8_t(required);

            // Do NOT add item.signature.
            for (const auto &item : signaturePairs) {
                ss << item.regid;
            }

            sigHash = ss.GetHash();
        }
        return sigHash;
    }

    virtual uint256 GetHash() const { return ComputeSignatureHash(); }
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CMulsigTx>(*this); }
    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);

    // If the sender has no regid before, geneate a regid for the sender.
    bool GenerateRegID(CTxExecuteContext &context, CAccount &account);
};

#endif //COIN_MULSIGTX_H
