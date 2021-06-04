// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Copyright (c) 2020 The IDeer Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PERSIST_RECORDDB_H
#define PERSIST_RECORDDB_H

#include <tuple>
#include <string>
#include <utility>
#include <vector>

#include "commons/arith_uint256.h"
#include "dbaccess.h"
#include "dbconf.h"
#include "dbiterator.h"
#include "entities/id.h"
#include "leveldbwrapper.h"

class CRecordDBCache {
public:
    CRecordDBCache() {}

    CRecordDBCache(CDBAccess *pDbAccess) : recordCache(pDbAccess) {
        assert(pDbAccess->GetDbNameType() == DBNameType::RECORD);
    }

    ~CRecordDBCache() {}

public:
    bool GetRecord(const CRegID &regid, const string &domain, const string &key, string &value);
    bool SaveRecord(const CRegID &regid, const string &domain, const string &key, const string &value);

    void Flush();

    uint32_t GetCacheSize() const { return recordCache.GetCacheSize(); }

    void SetBaseViewPtr(CRecordDBCache *pBaseIn) { recordCache.SetBase(&pBaseIn->recordCache); }

    void SetDbOpLogMap(CDBOpLogMap *pDbOpLogMapIn) { recordCache.SetDbOpLogMap(pDbOpLogMapIn); }

    bool UndoData() { return recordCache.UndoData(); }

private:
/*  CCompositeKVCache     prefixType            key              value           variable   */
/*  -------------------- --------------------   --------------  -------------   ------------*/
    // <std::tuple<regid, domain, key> -> value>
    CCompositeKVCache< dbk::RECORD,         std::tuple<string, string, string>,  string> recordCache;
};

#endif  // PERSIST_RECORDDB_H
