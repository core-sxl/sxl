// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CONFIG_SCOIN_H
#define CONFIG_SCOIN_H

#include <cstdint>
#include <unordered_map>
#include <string>
#include <cstdint>
#include <tuple>
#include "const.h"

using namespace std;

static const uint64_t FCOIN_VOTEMINE_EPOCH_FROM = 1665886560;  // Sun Oct 16 2022 10:16:00 GMT+0800
static const uint64_t FCOIN_VOTEMINE_EPOCH_TO   = 1792116960;  // Fri Oct 16 2026 10:16:00 GMT+0800

static const uint16_t FORCE_SETTLE_CDP_MAX_COUNT_PER_BLOCK = 1000;  // depends on TPS

static const double TRANSACTION_PRIORITY_CEILING      = 1000.0;  // Most trx priority is less than 1000.0
static const double PRICE_MEDIAN_TRANSACTION_PRIORITY = 10000.0;
static const double PRICE_FEED_TRANSACTION_PRIORITY   = 20000.0;

static const uint64_t ASSET_RISK_FEE_RATIO  = 4000;        // 40% * 10000, the ratio of asset fee into the risk riserve
static const uint64_t MIN_DEX_ORDER_AMOUNT  = 0.1 * COIN;  // min amount of dex order limit
static const uint64_t MAX_SETTLE_ITEM_COUNT = 10000;       // max count of dex settle item limit.

#endif
