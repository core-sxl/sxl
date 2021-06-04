// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assetdb.h"

#include "commons/uint256.h"
#include "commons/util.h"
#include "config/txbase.h"

bool CAssetDBCache::GetAsset(const TokenSymbol &tokenSymbol, CAsset &asset) {
    return assetCache.GetData(tokenSymbol, asset);
}

bool CAssetDBCache::HaveAsset(const TokenSymbol &tokenSymbol) {
    return assetCache.HaveData(tokenSymbol);
}

bool CAssetDBCache::SaveAsset(const CAsset &asset) {
    return assetCache.SetData(asset.symbol, asset);
}
bool CAssetDBCache::ExistAssetSymbol(const TokenSymbol &tokenSymbol) {
    return assetCache.HaveData(tokenSymbol);
}

shared_ptr<string> CAssetDBCache::CheckTransferCoinSymbol(const TokenSymbol &symbol) {
    if (kFeeSymbolSet.count(symbol)) {
        return nullptr;
    }

    size_t coinSymbolSize = symbol.size();
    if (coinSymbolSize == 0 || coinSymbolSize > MAX_ASSET_SYMBOL_LEN) {
        return std::make_shared<string>("empty or too long");
    }

    if ((coinSymbolSize < MIN_ASSET_SYMBOL_LEN && !kCoinTypeSet.count(symbol)) ||
        (coinSymbolSize >= MIN_ASSET_SYMBOL_LEN && !HaveAsset(symbol)))
        return std::make_shared<string>("unsupported symbol");

    return nullptr;
}