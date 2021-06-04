// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PERSIST_ASSETDB_H
#define PERSIST_ASSETDB_H

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "commons/arith_uint256.h"
#include "dbaccess.h"
#include "dbconf.h"
#include "dbiterator.h"
#include "entities/asset.h"
#include "leveldbwrapper.h"

/*  CCompositeKVCache     prefixType            key              value           variable           */
/*  -------------------- --------------------   --------------  -------------   --------------------- */
    // <asset_tokenSymbol -> asset>
typedef CCompositeKVCache< dbk::ASSET,         TokenSymbol,     CAsset>      DBAssetCache;


typedef CDBListGetter<DBAssetCache> CUserAssetsGetter;

class CAssetDBCache {
public:
    CAssetDBCache() {}

    CAssetDBCache(CDBAccess *pDbAccess) : assetCache(pDbAccess) {
        assert(pDbAccess->GetDbNameType() == DBNameType::ASSET);
    }

    ~CAssetDBCache() {}

public:
    bool GetAsset(const TokenSymbol &tokenSymbol, CAsset &asset);
    bool HaveAsset(const TokenSymbol &tokenSymbol);
    bool SaveAsset(const CAsset &asset);
    bool ExistAssetSymbol(const TokenSymbol &tokenSymbol);
    /**
     * check transfer coin symbol
     * return nullptr if succeed, else error msg
     */
    shared_ptr<string> CheckTransferCoinSymbol(const TokenSymbol &symbol);

    void Flush() { assetCache.Flush(); }

    uint32_t GetCacheSize() const { return assetCache.GetCacheSize(); }

    void SetBaseViewPtr(CAssetDBCache *pBaseIn) { assetCache.SetBase(&pBaseIn->assetCache); }

    void SetDbOpLogMap(CDBOpLogMap *pDbOpLogMapIn) { assetCache.SetDbOpLogMap(pDbOpLogMapIn); }

    bool UndoData() { return assetCache.UndoData(); }

    shared_ptr<CUserAssetsGetter> CreateUserAssetsGetter() { return make_shared<CUserAssetsGetter>(assetCache); }

private:
/*  CCompositeKVCache     prefixType            key              value           variable           */
/*  -------------------- --------------------   --------------  -------------   --------------------- */
    // <asset_tokenSymbol -> asset>
    DBAssetCache   assetCache;
};

#endif  // PERSIST_ASSETDB_H
