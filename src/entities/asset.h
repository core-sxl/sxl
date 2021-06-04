// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef ENTITIES_ASSET_H
#define ENTITIES_ASSET_H

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "commons/types.h"
#include "config/const.h"
#include "crypto/hash.h"
#include "id.h"
#include "vote.h"
#include "commons/json/json_spirit_utils.h"

using namespace json_spirit;
using namespace std;

typedef string TokenSymbol;     //8 chars max, E.g. SXL, WCNY, SXL-01D
typedef string TokenName;       //32 chars max, E.g. SXL Coins
typedef string CoinUnitName;    //defined in coin unit type table

struct ComboMoney {
    TokenSymbol     symbol;     //E.g. SXL
    uint64_t        amount;
    CoinUnitName    unit;       //E.g. savl

    ComboMoney() : symbol(SYMB::SXL), amount(0), unit(COIN_UNIT::SASX){};

    uint64_t GetSawiAmount() const {
        auto it = CoinUnitTypeTable.find(unit);
        if (it != CoinUnitTypeTable.end()) {
            return amount * it->second;
        } else {
            assert(false && "coin unit not found");
            return amount;
        }
    }
};

static const unordered_set<string> kCoinTypeSet = {SYMB::SXL};

class CAsset {
public:
    TokenSymbol symbol;     // asset symbol, E.g SXL
    CUserID owner_uid;      // creator or owner user id of the asset
    TokenName name;         // asset long name, E.g SXL coin
    uint64_t total_supply;  // boosted by 10^8 for the decimal part, max is 90 billion.
    bool mintable;          // whether this token can be minted in the future.
public:
    CAsset(): total_supply(0), mintable(false) {}

    CAsset(const TokenSymbol& symbolIn, const CUserID& ownerUseridIn, const TokenName& nameIn,
           uint64_t totalSupplyIn, bool mintableIn)
        : symbol(symbolIn),
          owner_uid(ownerUseridIn),
          name(nameIn),
          total_supply(totalSupplyIn),
          mintable(mintableIn){};

    IMPLEMENT_SERIALIZE(
        READWRITE(symbol);
        READWRITE(owner_uid);
        READWRITE(name);
        READWRITE(mintable);
        READWRITE(VARINT(total_supply));
    )

public:
    static bool CheckSymbolChar(const char ch) {
        return  ch >= 'A' && ch <= 'Z';
    }

    // @return nullptr if succeed, else err string
    static shared_ptr<string> CheckSymbol(const TokenSymbol& symbol) {
        size_t symbolSize = symbol.size();
        if (symbolSize < MIN_ASSET_SYMBOL_LEN || symbolSize > MAX_ASSET_SYMBOL_LEN)
            return make_shared<string>(strprintf("length=%d must be in range[%d, %d]", symbolSize, MIN_ASSET_SYMBOL_LEN,
                                                 MAX_ASSET_SYMBOL_LEN));

        for (auto ch : symbol) {
            if (!CheckSymbolChar(ch))
                return make_shared<string>("there is invalid char in symbol");
        }
        return nullptr;
    }

    bool IsEmpty() const { return owner_uid.IsEmpty(); }

    void SetEmpty() {
        owner_uid.SetEmpty();
        symbol.clear();
        name.clear();
        mintable = false;
        total_supply = 0;
    }
};

#endif //ENTITIES_ASSET_H
