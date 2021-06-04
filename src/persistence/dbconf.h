// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PERSIST_DBCONF_H
#define PERSIST_DBCONF_H

#include <leveldb/slice.h>
#include <string>

#include "config/version.h"
#include "commons/serialize.h"

typedef leveldb::Slice Slice;

#define DEF_DB_NAME_ENUM(enumType, enumName, cacheSize) enumType,
#define DEF_DB_NAME_ARRAY(enumType, enumName, cacheSize) enumName,
#define DEF_CACHE_SIZE_ARRAY(enumType, enumName, cacheSize) cacheSize,

//         DBNameType            DBName             DBCacheSize           description
//         ----------           --------------    --------------     ----------------------------
#define DB_NAME_LIST(DEFINE) \
    DEFINE( SYSPARAM,           "params",         (50 << 10) )      /* system params */ \
    DEFINE( ACCOUNT,            "accounts",       (50 << 20) )      /* accounts & account assets */ \
    DEFINE( ASSET,              "assets",         (100 << 10) )     /* asset registry */ \
    DEFINE( BLOCK,              "blocks",         (500 << 10) )     /* block & tx indexes */ \
    DEFINE( CONTRACT,           "contracts",      (50 << 20) )      /* contract */ \
    DEFINE( DELEGATE,           "delegates",      (100 << 10) )     /* delegates */ \
    DEFINE( CDP,                "cdps",           (50 << 20) )      /* cdp */ \
    DEFINE( CLOSEDCDP,          "closedcdps",     (1  << 20) )      /* closed cdp */ \
    DEFINE( DEX,                "dexes",          (50 << 20) )      /* dex */ \
    DEFINE( LOG,                "logs",           (100 << 10) )     /* log */ \
    DEFINE( RECEIPT,            "receipts",       (100 << 10) )     /* tx receipt */ \
    DEFINE( RECORD,             "record",         (50 << 20) )      /* record */ \
    /*                                                                  */  \
    /* Add new Enum elements above, DB_NAME_COUNT Must be the last one */ \
    DEFINE( DB_NAME_COUNT,        "",               0)                  /* enum count, must be the last one */

enum DBNameType {
    DB_NAME_LIST(DEF_DB_NAME_ENUM)
};


#define DB_NAME_NONE DB_NAME_COUNT

static const int32_t DBCacheSize[DBNameType::DB_NAME_COUNT + 1] {
    DB_NAME_LIST(DEF_CACHE_SIZE_ARRAY)
};

static const std::string kDbNames[DBNameType::DB_NAME_COUNT + 1] {
    DB_NAME_LIST(DEF_DB_NAME_ARRAY)
};

inline const std::string& GetDbName(DBNameType dbNameType) {
    assert(dbNameType >= 0 && dbNameType < DBNameType::DB_NAME_COUNT);
    return kDbNames[dbNameType];
}

namespace dbk {


    //                 type        name(prefix)  db name             description
    //               ----------    ------------ -------------  -----------------------------------
    #define DBK_PREFIX_LIST(DEFINE) \
        DEFINE( EMPTY,                "",      DB_NAME_NONE )  /* empty prefix  */ \
        /*                                                                      */ \
        /**** single-value sys_conf db (global parameters)                      */ \
        DEFINE( SYS_PARAM,            "sysp",   SYSPARAM )       /* conf{$ParamName} --> $ParamValue */ \
        /*** Asset Registry DB */ \
        DEFINE( ASSET,                "asst",   ASSET )          /* asst{$AssetName} --> $Asset */ \
        DEFINE( ASSET_TRADING_PAIR,   "atdp",   ASSET )          /* asst{$AssetName} --> $Asset */ \
        /**** block db                                                                          */ \
        DEFINE( BLOCK_INDEX,          "bidx",   BLOCK )         /* pbfl --> $nFile */ \
        DEFINE( BLOCKFILE_NUM_INFO,   "bfni",   BLOCK )         /* BlockFileNum --> $BlockFileInfo */ \
        DEFINE( LAST_BLOCKFILE,       "ltbf",   BLOCK )         /* [prefix] --> $LastBlockFile */ \
        DEFINE( REINDEX,              "ridx",   BLOCK )         /* [prefix] --> $Reindex = 1 | 0 */ \
        DEFINE( FLAG,                 "flag",   BLOCK )         /* [prefix] --> $Flag = 1 | 0 */ \
        DEFINE( BEST_BLOCKHASH,       "bbkh",   BLOCK )         /* [prefix] --> $BestBlockHash */ \
        DEFINE( TXID_DISKINDEX,       "tidx",   BLOCK )         /* tidx{$txid} --> $DiskTxPos */ \
        /**** account db                                                                      */ \
        DEFINE( REGID_KEYID,          "rkey",   ACCOUNT )       /* rkey{$RegID} --> $KeyId */ \
        DEFINE( NICKID_KEYID,         "nkey",   ACCOUNT )       /* nkey{$NickID} --> $KeyId */ \
        DEFINE( KEYID_ACCOUNT,        "idac",   ACCOUNT )       /* idac{$KeyID} --> $CAccount */ \
        DEFINE( KEYID_ACCOUNT_TOKEN,  "idat",   ACCOUNT )       /* idat{$KeyID}{tokenSymbol} --> $free_amount, $frozen_amount */ \
        /**** contract db                                                                      */ \
        DEFINE( CONTRACT_DEF,         "cdef",   CONTRACT )      /* cdef{$ContractRegId} --> $ContractContent */ \
        DEFINE( CONTRACT_DATA,        "cdat",   CONTRACT )      /* cdat{$RegId}{$DataKey} --> $Data */ \
        DEFINE( CONTRACT_ITEM_NUM,    "citn",   CONTRACT )      /* citn{$ContractRegId} --> $total_num_of_contract_i */ \
        DEFINE( CONTRACT_ACCOUNT,     "cacc",   CONTRACT )      /* cacc{$ContractRegId}{$AccUserId} --> appUserAccount */ \
        /**** delegate db                                                                      */ \
        DEFINE( VOTE,                 "vote",   DELEGATE )      /* "vote{(uint64t)MAX - $voteNum}{$RegId} --> 1 */ \
        DEFINE( REGID_VOTE,           "ridv",   DELEGATE )      /* "ridv{} --> $votes" */ \
        /**** tx receipt db                                                                    */ \
        DEFINE( TX_RECEIPT,           "txrc",   RECEIPT )       /* txrc{$txid} --> $receipts */ \
        /**** record db                                                                     */ \
        DEFINE( RECORD,               "rdkv",   RECORD )        /* rdkv{$RegID}{$domain}{$key} --> $value */ \
        /* Add new Enum elements above, PREFIX_COUNT Must be the last one              */ \
        DEFINE( PREFIX_COUNT,         "",       DB_NAME_NONE)   /* enum count, must be the last one */


    #define DEF_DB_PREFIX_ENUM(enumType, enumName, dbName) enumType,
    #define DEF_DB_PREFIX_NAME_ARRAY(enumType, enumName, dbName) enumName,
    #define DEF_DB_PREFIX_NAME_MAP(enumType, enumName, dbName) { enumName, enumType },
    #define DEF_DB_PREFIX_DBNAME(enumType, enumName, dbName) DBNameType::dbName,

    enum PrefixType {
        DBK_PREFIX_LIST(DEF_DB_PREFIX_ENUM)
    };

    static const std::string kPrefixNames[PREFIX_COUNT + 1] = {
        DBK_PREFIX_LIST(DEF_DB_PREFIX_NAME_ARRAY)
    };

    static const std::map<std::string, PrefixType> gPrefixNameMap = {
        DBK_PREFIX_LIST(DEF_DB_PREFIX_NAME_MAP)
    };

    static const DBNameType kDbPrefix2DbName[PREFIX_COUNT + 1] = {
        DBK_PREFIX_LIST(DEF_DB_PREFIX_DBNAME)
    };

    inline const std::string& GetKeyPrefix(PrefixType prefixType) {
        assert(prefixType >= 0 && prefixType <= PREFIX_COUNT);
        return kPrefixNames[prefixType];
    };

    inline DBNameType GetDbNameEnumByPrefix(PrefixType prefixType) {
        assert(prefixType > 0 && prefixType <= PREFIX_COUNT);
        return kDbPrefix2DbName[prefixType];
    };

    inline PrefixType ParseKeyPrefixType(const std::string &keyPrefix) {
        auto it = gPrefixNameMap.find(keyPrefix);
        if (it != gPrefixNameMap.end())
            return it->second;
        return EMPTY;
    };

    template<typename KeyElement>
    std::string GenDbKey(PrefixType keyPrefixType, const KeyElement &keyElement) {
        CDataStream ssKeyTemp(SER_DISK, CLIENT_VERSION);
        assert(keyPrefixType != EMPTY);
        const string &prefix = GetKeyPrefix(keyPrefixType);
        ssKeyTemp.write(prefix.c_str(), prefix.size()); // write buffer only, exclude size prefix
        ssKeyTemp << keyElement;
        return std::string(ssKeyTemp.begin(), ssKeyTemp.end());
    }

    template<typename KeyElement>
    bool ParseDbKey(const Slice& slice, PrefixType keyPrefixType, KeyElement &keyElement) {
        assert(slice.size() > 0);
        const string &prefix = GetKeyPrefix(keyPrefixType);
        if (!prefix.empty() && !slice.starts_with(Slice(prefix))) {
            return false;
        }

        CDataStream ssKeyTemp(slice.data(), slice.data() + slice.size(), SER_DISK, CLIENT_VERSION);
        ssKeyTemp.ignore(prefix.size());
        ssKeyTemp >> keyElement;

        return true;
    }

    template<typename KeyElement>
    bool ParseDbKey(const std::string& key, PrefixType keyPrefixType, KeyElement &keyElement) {
        return ParseDbKey(Slice(key), keyPrefixType, keyElement);
    }

    // CDBTailKey
    // support partial match.
    // must be last element of pair or tuple key,
    template<uint32_t __MAX_KEY_SIZE>
    class CDBTailKey {
    public:
        enum { MAX_KEY_SIZE = __MAX_KEY_SIZE };
    private:
        string key;
    public:
        CDBTailKey() {}
        CDBTailKey(const string &keyIn): key(keyIn) { assert(keyIn.size() <= MAX_KEY_SIZE); }

        const string& GetKey() const { return key; }

        inline bool StartWith(const CDBTailKey& prefix) const {
            return key.compare(0, prefix.key.size(), prefix.key) == 0;
        }

        inline uint32_t GetSerializeSize(int32_t nType, int32_t nVersion) const {
            return key.size();
        }

        void Serialize(CDataStream &s, int nType, int nVersion) const {
            s.write(key.data(), key.size());
        }

        void Unserialize(CDataStream &s, int nType, int nVersion) {
            if (s.size() > MAX_KEY_SIZE) {
                throw ios_base::failure("CDBTailKey::Unserialize size excceded max size");
            }
            // read key from s.begin() to s.end(), s.begin() is current read pos
            key.insert(key.end(), s.begin(), s.end());
        }

        bool operator==(const CDBTailKey &other) {
            return key == other.key;
        }

        bool operator<(const CDBTailKey &other) const {
            return this->key < other.key;
        }

        bool IsEmpty() const { return key.empty(); }

        void SetEmpty() { key.clear(); }

    };
}

class SliceIterator {
public:
    SliceIterator(Slice &sliceIn): slice(sliceIn) {}
    inline const char* begin() const { return slice.data(); };
    inline const char* end() const { return slice.data() + slice.size(); };
private:
    Slice &slice;
};

#endif  // PERSIST_DBCONF_H
