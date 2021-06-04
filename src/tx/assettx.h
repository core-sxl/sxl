// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TX_ASSET_H
#define TX_ASSET_H

#include "tx.h"

Object AssetToJson(const CAccountDBCache &accountCache, const CAsset &asset);

/**
 * Issue a new asset onto Chain
 */
class CAssetIssueTx: public CBaseTx {
public:
    CAsset asset;  // asset

public:
    CAssetIssueTx() : CBaseTx(ASSET_ISSUE_TX){};
    CAssetIssueTx(const CUserID &txUidIn, int32_t validHeightIn, uint64_t fees, const CAsset &assetIn)
        : CBaseTx(ASSET_ISSUE_TX, txUidIn, validHeightIn, fees), asset(assetIn) {}
    ~CAssetIssueTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(asset);
        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees) << asset;

            sigHash = ss.GetHash();
        }
        return sigHash;
    }

    virtual TxID GetHash() const { return ComputeSignatureHash(); }
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CAssetIssueTx>(*this); }

    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);
};

class CAssetUpdateData {
public:
    class CNullData {
    public:
        friend bool operator==(const CNullData &a, const CNullData &b) { return true; }
        friend bool operator<(const CNullData &a, const CNullData &b) { return true; }
    };

public:
    enum UpdateType : uint8_t {
        UPDATE_NONE = 0,
        OWNER_UID   = 1,
        NAME        = 2,
        MINT_AMOUNT = 3,
    };
    typedef boost::variant<CNullData,
        CUserID, // owner_uid
        string,  // name
        uint64_t // mint_amount
    > ValueType;
private:
    UpdateType type; // update type
    ValueType value; // update value

public:
    static std::shared_ptr<UpdateType> ParseUpdateType(const string& str);

    static const string& GetUpdateTypeName(UpdateType type);
public:
    CAssetUpdateData(): type(UPDATE_NONE), value(CNullData()) {}

    void Set(const CUserID &ownerUid);

    void Set(const string &name);

    void Set(const uint64_t &mintAmount);

    UpdateType GetType() const { return type; }

    template <typename T_Value>
    T_Value &get() {
        return boost::get<T_Value>(value);
    }
    template <typename T_Value>
    const T_Value &get() const {
        return boost::get<T_Value>(value);
    }

public:

    inline unsigned int GetSerializeSize(int serializedType, int nVersion) const {
        switch (type) {
            case OWNER_UID:     return sizeof(uint8_t) + get<CUserID>().GetSerializeSize(serializedType, nVersion);
            case NAME:          return sizeof(uint8_t) + ::GetSerializeSize(get<string>(), serializedType, nVersion);
            case MINT_AMOUNT:   return sizeof(uint8_t) + ::GetSerializeSize(VARINT(get<uint64_t>()), serializedType, nVersion);
            default: break;
        }
        return 0;
    }

    template <typename Stream>
    void Serialize(Stream &s, int serializedType, int nVersion) const {
        s << (uint8_t)type;
        switch (type) {
            case OWNER_UID:     s << get<CUserID>(); break;
            case NAME:          s << get<string>(); break;
            case MINT_AMOUNT:   s << VARINT(get<uint64_t>()); break;
            default: {
                LogPrint("ERROR", "CAssetUpdateData::Serialize(), Invalid Asset update type=%d\n", type);
                throw ios_base::failure("Invalid Asset update type");
            }
        }
    }

    template <typename Stream>
    void Unserialize(Stream &s, int serializedType, int nVersion) {
        s >> ((uint8_t&)type);
        switch (type) {
            case OWNER_UID: {
                CUserID uid;
                s >> uid;
                value = uid;
                break;
            }
            case NAME: {
                string name;
                s >> name;
                value = name;
                break;
            }
            case MINT_AMOUNT: {
                uint64_t mintAmount;
                s >> VARINT(mintAmount);
                value = mintAmount;
                break;
            }
            default: {
                LogPrint("ERROR", "CAssetUpdateData::Unserialize(), Invalid Asset update type=%d\n", type);
                throw ios_base::failure("Invalid Asset update type");
            }
        }
    }

    string ValueToString() const;

    string ToString(const CAccountDBCache &accountCache) const;

    Object ToJson(const CAccountDBCache &accountCache) const;
};

/**
 * Update an existing asset from Chain
 */
class CAssetUpdateTx: public CBaseTx {

public:
    TokenSymbol asset_symbol;       // symbol of asset that needs to be updated
    CAssetUpdateData update_data;   // update data(type, value)

public:
    CAssetUpdateTx() : CBaseTx(ASSET_UPDATE_TX) {}
    CAssetUpdateTx(const CUserID &txUidIn, int32_t validHeightIn, uint64_t feesIn, const TokenSymbol &assetSymbolIn,
                   const CAssetUpdateData &updateData)
        : CBaseTx(ASSET_UPDATE_TX, txUidIn, validHeightIn, feesIn),
          asset_symbol(assetSymbolIn),
          update_data(updateData) {}
    ~CAssetUpdateTx() {}

    IMPLEMENT_SERIALIZE(
        READWRITE(VARINT(this->nVersion));
        nVersion = this->nVersion;
        READWRITE(VARINT(valid_height));
        READWRITE(txUid);
        READWRITE(VARINT(llFees));

        READWRITE(asset_symbol);
        READWRITE(update_data);
        READWRITE(signature);
    )

    TxID ComputeSignatureHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << VARINT(nVersion) << uint8_t(nTxType) << VARINT(valid_height) << txUid << VARINT(llFees)
               << asset_symbol << update_data;

            sigHash = ss.GetHash();
        }
        return sigHash;
    }

    virtual TxID GetHash() const { return ComputeSignatureHash(); }
    virtual std::shared_ptr<CBaseTx> GetNewInstance() const { return std::make_shared<CAssetUpdateTx>(*this); }

    virtual string ToString(CAccountDBCache &accountCache);
    virtual Object ToJson(const CAccountDBCache &accountCache) const;

    virtual bool CheckTx(CTxExecuteContext &context);
    virtual bool ExecuteTx(CTxExecuteContext &context);

};

#endif  // TX_ASSET_H
