// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TX_CONTRACT_H
#define TX_CONTRACT_H

#include "tx.h"
#include "entities/contract.h"

/**#################### Universal Contract Deploy & Invoke Class Definitions ##############################**/
class CContractDeployTx : public CBaseTx {
public:
    CUniversalContract contract;  // contract script content

public:
    CContractDeployTx(): CBaseTx(CONTRACT_DEPLOY_TX) {}
    ~CContractDeployTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(contract);

        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees) << contract;

            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    virtual uint256 GetHash() const { return ComputeSignatureHash(); }
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CContractDeployTx>(*this); }
    virtual uint64_t GetFuel(int32_t height, uint32_t fuelRate);
    virtual string ToString(CAccountDBCache &accountView);
    virtual Object ToJson(const CAccountDBCache &accountView) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

class CContractInvokeTx : public CBaseTx {
public:
    mutable CUserID app_uid;  // app regid
    string arguments;         // arguments to invoke a contract method
    TokenSymbol coin_symbol;
    uint64_t coin_amount;  // transfer amount to contract account

public:
    CContractInvokeTx() : CBaseTx(CONTRACT_INVOKE_TX) {}
    ~CContractInvokeTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(app_uid);
        READWRITE(arguments);
        READWRITE(coin_symbol);
        READWRITE(VARINT(coin_amount));

        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees) << app_uid
               << arguments << coin_symbol << VARINT(coin_amount);

            sigHash = ss.GetHash();
        }
        return sigHash;
    }

    virtual uint256 GetHash() const { return ComputeSignatureHash(); }
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CContractInvokeTx>(*this); }
    virtual string ToString(CAccountDBCache &accountView);
    virtual Object ToJson(const CAccountDBCache &accountView) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

#endif  // TX_CONTRACT_H
