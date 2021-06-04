// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DELEGATE_H
#define DELEGATE_H

#include "tx.h"

class CDelegateVoteTx : public CBaseTx {
public:
    vector<CCandidateVote> candidateVotes;  //!< candidate-delegate votes, max size is 22

public:
    CDelegateVoteTx(const CUserID &txUidIn, const vector<CCandidateVote> &candidateVotesIn, const uint64_t feesIn,
                    const int32_t validHeightIn)
        : CBaseTx(DELEGATE_VOTE_TX, txUidIn, validHeightIn, feesIn), candidateVotes(candidateVotesIn) {}
    CDelegateVoteTx() : CBaseTx(DELEGATE_VOTE_TX) {}
    ~CDelegateVoteTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(candidateVotes);
        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees)
               << candidateVotes;

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    virtual uint256 GetHash() const { return ComputeSignatureHash(); }
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CDelegateVoteTx>(*this); }
    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif