// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COIN_CHAIN_PARAMS_H
#define COIN_CHAIN_PARAMS_H
#include <memory>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <vector>

#include "entities/id.h"
#include "commons/uint256.h"
#include "commons/arith_uint256.h"
#include "commons/util.h"
#include "config/scoin.h"

using namespace std;

#define MESSAGE_START_SIZE 4
typedef uint8_t MessageStartChars[MESSAGE_START_SIZE];

class CAddress;
class CBaseTx;
class CBlock;

struct CDNSSeedData {
    string name, host;
    CDNSSeedData(const string& strName, const string& strHost) : name(strName), host(strHost) {}
};

typedef enum {
    MAIN_NET            = 0,
    TEST_NET            = 1,
    REGTEST_NET         = 2,
    NULL_NETWORK_TYPE   = 3
} NET_TYPE;

typedef enum {
    PUBKEY_ADDRESS,     //!< PUBKEY_ADDRESS
    SCRIPT_ADDRESS,     //!< SCRIPT_ADDRESS
    SECRET_KEY,         //!< SECRET_KEY
    EXT_PUBLIC_KEY,     //!< EXT_PUBLIC_KEY
    EXT_SECRET_KEY,     //!< EXT_SECRET_KEY
    ACC_ADDRESS,        //!< ACC_ADDRESS
    MAX_BASE58_TYPES    //!< MAX_BASE58_TYPES
} Base58Type;

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Coin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CBaseParams {
protected:
    mutable bool fDebugAll;
    mutable bool fDebug;
    mutable bool fPrintLogToConsole;
    mutable bool fPrintLogToFile;
    mutable bool fLogTimestamps;
    mutable bool fLogPrintFileLine;
    mutable bool fServer;
    mutable bool fImporting;
    mutable bool fReindex;
    mutable bool fTxIndex;
    mutable bool fLogFailures;
    mutable bool fGenReceipt;
    mutable int64_t nTimeBestReceived;
    mutable uint32_t nCacheSize;
    mutable int32_t nTxCacheHeight;
    mutable uint32_t nLogMaxSize;  // to limit the maximum log file size in bytes

public:
    virtual ~CBaseParams() {}

    virtual bool InitializeConfig() {
        fServer = GetBoolArg("-rpcserver", false);

        m_mapMultiArgs["-debug"].push_back("ERROR");  // Enable ERROR logger by default
        fDebug = !m_mapMultiArgs["-debug"].empty();
        if (fDebug) {
            fDebugAll          = GetBoolArg("-logprintall", false);
            fPrintLogToConsole = GetBoolArg("-logprinttoconsole", false);
            fLogTimestamps     = GetBoolArg("-logtimestamps", true);
            fPrintLogToFile    = GetBoolArg("-logprinttofile", false);
            fLogPrintFileLine  = GetBoolArg("-logprintfileline", false);
        }

        nLogMaxSize = GetArg("-logmaxsize", 100) * 1024 * 1024;  // 100 MB

        return true;
    }

public:
    int GetConnectTimeOut() const {
        int nConnectTimeout = 5000;
        if (m_mapArgs.count("-timeout")) {
            int nNewTimeout = GetArg("-timeout", 5000);
            if (nNewTimeout > 0 && nNewTimeout < 600000) nConnectTimeout = nNewTimeout;
        }
        return nConnectTimeout;
    }
    bool IsDebug() const { return fDebug; }
    bool IsDebugAll() const { return fDebugAll; }
    bool IsPrintLogToConsole() const { return fPrintLogToConsole; }
    bool IsPrintLogToFile() const { return fPrintLogToFile; }
    bool IsLogTimestamps() const { return fPrintLogToFile; }
    bool IsLogPrintLine() const { return fLogPrintFileLine; }
    bool IsServer() const { return fServer; }
    bool IsImporting() const { return fImporting; }
    bool IsReindex() const { return fReindex; }
    bool IsTxIndex() const { return fTxIndex; }
    bool IsLogFailures() const { return fLogFailures; };
    bool IsGenReceipt() const { return fGenReceipt; };
    int64_t GetBestRecvTime() const { return nTimeBestReceived; }
    uint32_t GetCacheSize() const { return nCacheSize; }
    int32_t GetTxCacheHeight() const { return nTxCacheHeight; }
    uint32_t GetLogMaxSize() const { return nLogMaxSize; }
    void SetImporting(bool flag) const { fImporting = flag; }
    void SetReIndex(bool flag) const { fReindex = flag; }
    void SetTxIndex(bool flag) const { fTxIndex = flag; }
    void SetLogFailures(bool flag) const { fLogFailures = flag; }
    void SetGenReceipt(bool flag) const { fGenReceipt = flag; }
    void SetBestRecvTime(int64_t nTime) const { nTimeBestReceived = nTime; }
    const MessageStartChars& MessageStart() const { return pchMessageStart; }
    int32_t GetDefaultPort() const { return nDefaultPort; }
    uint32_t GetBlockInterval() const { return nBlockInterval; }
    virtual uint64_t GetMaxFee() const { return 1000 * COIN; }
    virtual const CBlock& GenesisBlock() const = 0;
    const uint256& GetGenesisBlockHash() const { return genesisBlockHash; }
    bool CreateGenesisBlockRewardTx(vector<std::shared_ptr<CBaseTx> >& vptx, NET_TYPE type);
    bool CreateGenesisDelegateTx(vector<std::shared_ptr<CBaseTx> >& vptx, NET_TYPE type);
    virtual bool RequireRPCPassword() const { return true; }
    const string& DataDir() const { return strDataDir; }
    virtual NET_TYPE NetworkID() const = 0;
    const vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const vector<uint8_t>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const string& PubkeyAddressPrefix() const { return pubkeyAddressPrefix; }
    virtual const vector<CAddress>& FixedSeeds() const = 0;
    virtual bool IsInFixedSeeds(CAddress& addr)        = 0;
    int RPCPort() const { return nRPCPort; }
    static bool InitializeParams(int argc, const char* const argv[]);
    static int64_t GetArg(const string& strArg, int64_t nDefault);
    static string GetArg(const string& strArg, const string& strDefault);
    static bool GetBoolArg(const string& strArg, bool fDefault);
    static bool SoftSetArg(const string& strArg, const string& strValue);
    static bool SoftSetBoolArg(const string& strArg, bool fValue);
    static bool IsArgCount(const string& strArg);
    static bool SoftSetArgCover(const string& strArg, const string& strValue);
    static void EraseArg(const string& strArgKey);
    static void ParseParameters(int argc, const char* const argv[]);
    static const vector<string>& GetMultiArgs(const string& strArg);
    static int GetArgsSize();
    static int GetMultiArgsSize();
    static map<string, string> GetMapArgs() { return m_mapArgs; }
    static map<string, vector<string> > GetMapMultiArgs() { return m_mapMultiArgs; }
    static void SetMapArgs(const map<string, string>& mapArgs) { m_mapArgs = mapArgs; }
    static void SetMultiMapArgs(const map<string, vector<string> >& mapMultiArgs) { m_mapMultiArgs = mapMultiArgs; }

protected:
    static map<string, string> m_mapArgs;
    static map<string, vector<string> > m_mapMultiArgs;

protected:
    CBaseParams();

    uint256 genesisBlockHash;
    MessageStartChars pchMessageStart;
    int32_t nDefaultPort;
    int32_t nRPCPort;
    string alartPKey;
    uint32_t nBlockInterval;
    string strDataDir;
    vector<CDNSSeedData> vSeeds;
    vector<uint8_t> base58Prefixes[MAX_BASE58_TYPES];
    string pubkeyAddressPrefix;
};

extern CBaseParams &SysCfg();

// Note: it's deliberate that this returns "false" for regression test mode.
inline bool TestNet() { return SysCfg().NetworkID() == TEST_NET; }

inline bool RegTest() { return SysCfg().NetworkID() == REGTEST_NET; }

// write for test code
extern const CBaseParams& SysParamsMain();

// write for test code
extern const CBaseParams& SysParamsTest();

// write for test code
extern const CBaseParams& SysParamsReg();

#endif
