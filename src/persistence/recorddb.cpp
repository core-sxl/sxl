// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "recorddb.h"

#include "commons/uint256.h"
#include "commons/util.h"
#include "config/txbase.h"

bool CRecordDBCache::GetRecord(const CRegID &regid, const string &domain, const string &key, string &value) {
    auto finalKey = std::make_tuple(regid.ToRawString(), domain, key);
    return recordCache.GetData(finalKey, value);
}

bool CRecordDBCache::SaveRecord(const CRegID &regid, const string &domain, const string &key, const string &value) {
    auto finalKey = std::make_tuple(regid.ToRawString(), domain, key);
    return recordCache.SetData(finalKey, value);
}

void CRecordDBCache::Flush() { recordCache.Flush(); }