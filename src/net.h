// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COIN_NET_H
#define COIN_NET_H

#include "commons/bloom.h"
#include "commons/limitedmap.h"
#include "commons/mruset.h"
#include "commons/random.h"
#include "commons/uint256.h"
#include "commons/util.h"
#include "commons/compat/compat.h"
#include "crypto/hash.h"
#include "netbase.h"
#include "p2p/protocol.h"
#include "sync.h"

#include <stdint.h>
#include <deque>
#include <arpa/inet.h>

#include <openssl/rand.h>
#include <boost/foreach.hpp>
#include <boost/signals2/signal.hpp>

class CAddrMan;
class CBlockIndex;
class CNode;


/** The maximum number of entries in an 'inv' protocol message */
static const uint32_t MAX_INV_SZ = 50000;
/** The maximum number of entries in mapAskFor */
static const size_t MAPASKFOR_MAX_SZ = MAX_INV_SZ;
/** The maximum number of new addresses to accumulate before announcing. */
static const uint32_t MAX_ADDR_TO_SEND = 1000;

inline uint32_t ReceiveFloodSize() { return 1000 * SysCfg().GetArg("-maxreceivebuffer", 5 * 1000); }
inline uint32_t SendBufferSize() { return 1000 * SysCfg().GetArg("-maxsendbuffer", 1 * 1000); }

void AddOneShot(string strDest);
bool RecvLine(SOCKET hSocket, string& strLine);
void AddressCurrentlyConnected(const CService& addr);
CNode* FindNode(const CNetAddr& ip);
CNode* FindNode(const CService& ip);
CNode* ConnectNode(CAddress addrConnect, const char* strDest = nullptr);
void MapPort(bool fUseUPnP);
uint16_t GetListenPort();
bool BindListenPort(const CService& bindAddr, string& strError = REF(string()));
void StartNode(boost::thread_group& threadGroup);
bool StopNode();
void SocketSendData(CNode* pNode);

typedef int32_t NodeId;

// Signals for message handling
struct CNodeSignals {
    boost::signals2::signal<int32_t()> GetHeight;
    boost::signals2::signal<bool(CNode*)> ProcessMessages;
    boost::signals2::signal<bool(CNode*, bool)> SendMessages;
    boost::signals2::signal<void(NodeId, const CNode*)> InitializeNode;
    boost::signals2::signal<void(NodeId)> FinalizeNode;
};

CNodeSignals& GetNodeSignals();

enum {
    LOCAL_NONE,    // unknown
    LOCAL_IF,      // address a local interface listens on
    LOCAL_BIND,    // address explicit bound to
    LOCAL_UPNP,    // address reported by UPnP
    LOCAL_HTTP,    // address reported by whatismyip.com and similar
    LOCAL_MANUAL,  // address explicitly specified (-externalip=)

    LOCAL_MAX
};

void SetLimited(enum Network net, bool fLimited = true);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr& addr);
bool AddLocal(const CService& addr, int32_t nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int32_t nScore = LOCAL_NONE);
bool SeenLocal(const CService& addr);
bool IsLocal(const CService& addr);
bool GetLocal(CService& addr, const CNetAddr* paddrPeer = nullptr);
bool IsReachable(const CNetAddr& addr);
void SetReachable(enum Network net, bool fFlag = true);
CAddress GetLocalAddress(const CNetAddr* paddrPeer = nullptr);

extern bool fDiscover;
extern uint64_t nLocalServices;
extern uint64_t nLocalHostNonce;
extern CAddrMan addrman;
extern int32_t nMaxConnections;

extern vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern map<CInv, CDataStream> mapRelay;
extern deque<pair<int64_t, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;
extern limitedmap<CInv, int64_t> mapAlreadyAskedFor;

extern vector<string> vAddedNodes;
extern CCriticalSection cs_vAddedNodes;

extern NodeId nLastNodeId;
extern CCriticalSection cs_nLastNodeId;

struct LocalServiceInfo {
    int32_t nScore;
    int32_t nPort;
};

extern CCriticalSection cs_mapLocalHost;
extern map<CNetAddr, LocalServiceInfo> mapLocalHost;

class CNodeStats {
public:
    NodeId nodeid;
    uint64_t nServices;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    string addrName;
    int32_t nVersion;
    string cleanSubVer;
    bool fInbound;
    int32_t nStartingHeight;
    uint64_t nSendBytes;
    uint64_t nRecvBytes;
    bool fSyncNode;
    double dPingTime;
    double dPingWait;
    string addrLocal;
};

class CNetMessage {
public:
    bool in_data;  // parsing header (false) or data (true)

    CDataStream hdrbuf;  // partially received header
    CMessageHeader hdr;  // complete header
    uint32_t nHdrPos;

    CDataStream vRecv;  // received message data
    uint32_t nDataPos;

    CNetMessage(int32_t nTypeIn, int32_t nVersionIn) : hdrbuf(nTypeIn, nVersionIn), vRecv(nTypeIn, nVersionIn) {
        hdrbuf.resize(24);
        in_data  = false;
        nHdrPos  = 0;
        nDataPos = 0;
    }

    bool complete() const {
        if (!in_data)
            return false;
        return (hdr.nMessageSize == nDataPos);
    }

    void SetVersion(int32_t nVersionIn) {
        hdrbuf.SetVersion(nVersionIn);
        vRecv.SetVersion(nVersionIn);
    }

    int32_t readHeader(const char* pch, uint32_t nBytes);
    int32_t readData(const char* pch, uint32_t nBytes);
};

/** Information about a peer */
class CNode {
public:
    // socket
    uint64_t nServices;
    SOCKET hSocket;
    CDataStream ssSend;
    size_t nSendSize;    // total size of all vSendMsg entries
    size_t nSendOffset;  // offset inside the first vSendMsg already sent
    uint64_t nSendBytes;
    deque<CSerializeData> vSendMsg;
    CCriticalSection cs_vSend;

    deque<CInv> vRecvGetData;  // strCommand == "getdata ?????????inv
    deque<CNetMessage> vRecvMsg;
    CCriticalSection cs_vRecvMsg;
    uint64_t nRecvBytes;
    int32_t nRecvVersion;

    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nLastSendEmpty;
    int64_t nTimeConnected;
    CAddress addr;
    string addrName;
    CService addrLocal;
    int32_t nVersion; //protocol version
    // strSubVer is whatever byte array we read from the wire. However, this field is intended
    // to be printed out, displayed to humans in various forms and so on. So we sanitize it and
    // store the sanitized version in cleanSubVer. The original should be used when dealing with
    // the network or wire types and the cleaned string used when displayed or logged.
    string strSubVer, cleanSubVer;
    bool fOneShot;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fSuccessfullyConnected;
    bool fDisconnect;
    // We use fRelayTxes for two purposes -
    // a) it allows us to not relay tx invs before receiving the peer's version message
    // b) the peer may tell us in their version message that we should not relay tx invs
    //    until they have initialized their bloom filter.
    bool fRelayTxes;
    CSemaphoreGrant grantOutbound;
    CCriticalSection cs_filter;
    CBloomFilter* pFilter;
    int32_t nRefCount;
    NodeId id;

protected:
    // Denial-of-service detection/prevention
    // Key is IP address, value is banned-until-time
    static map<CNetAddr, int64_t> setBanned;
    static CCriticalSection cs_setBanned;

    // Basic fuzz-testing
    void Fuzz(int32_t nChance);  // modifies ssSend

public:
    uint256 hashContinue;                   // getblocks the next batch of inventory????????? ????????????
    CBlockIndex* pIndexLastGetBlocksBegin;  //??????????????????  ?????????????????????chainActive.Tip()
    uint256 hashLastGetBlocksEnd;           // ??????????????????????????????????????? hash GetOrphanRoot(hash)
    int32_t nStartingHeight;                // Start block sync, current height
    bool fStartSync;

    // flood relay
    vector<CAddress> vAddrToSend;
    mruset<CAddress> setAddrKnown;
    bool fGetAddr;
    set<uint256> setKnown;  // alertHash

    // inventory based relay
    mruset<CInv> setInventoryKnown;  //??????????????????inv
    vector<CInv> vInventoryToSend;   //????????????inv
    CCriticalSection cs_inventory;
    multimap<int64_t, CInv> mapAskFor;  //??????????????????????????????, a priority queue

    // Ping time measurement
    uint64_t nPingNonceSent;
    int64_t nPingUsecStart;
    int64_t nPingUsecTime;
    bool fPingQueued;

    CNode(SOCKET hSocketIn, CAddress addrIn, string addrNameIn = "", bool fInboundIn = false)
        : ssSend(SER_NETWORK, INIT_PROTO_VERSION), setAddrKnown(5000) {
        nServices                = 0;
        hSocket                  = hSocketIn;
        nRecvVersion             = INIT_PROTO_VERSION;
        nLastSend                = 0;
        nLastRecv                = 0;
        nSendBytes               = 0;
        nRecvBytes               = 0;
        nLastSendEmpty           = GetTime();
        nTimeConnected           = GetTime();
        addr                     = addrIn;
        addrName                 = addrNameIn == "" ? addr.ToStringIPPort() : addrNameIn;
        nVersion                 = 0;
        strSubVer                = "";
        fOneShot                 = false;
        fClient                  = false;  // set by version message
        fInbound                 = fInboundIn;
        fNetworkNode             = false;
        fSuccessfullyConnected   = false;
        fDisconnect              = false;
        nRefCount                = 0;
        nSendSize                = 0;
        nSendOffset              = 0;
        hashContinue             = uint256();
        pIndexLastGetBlocksBegin = 0;
        hashLastGetBlocksEnd     = uint256();
        nStartingHeight          = -1;
        fStartSync               = false;
        fGetAddr                 = false;
        fRelayTxes               = false;
        setInventoryKnown.max_size(SendBufferSize() / 1000);
        pFilter        = new CBloomFilter();
        nPingNonceSent = 0;
        nPingUsecStart = 0;
        nPingUsecTime  = 0;
        fPingQueued    = false;

        {
            LOCK(cs_nLastNodeId);
            id = nLastNodeId++;
        }

        // Be shy and don't send version until we hear
        if (hSocket != INVALID_SOCKET && !fInbound)
            PushVersion();

        GetNodeSignals().InitializeNode(GetId(), this);
    }

    ~CNode() {
        if (hSocket != INVALID_SOCKET) {
            closesocket(hSocket);
            hSocket = INVALID_SOCKET;
        }
        if (pFilter)
            delete pFilter;
        GetNodeSignals().FinalizeNode(GetId());
    }

private:
    // Network usage totals
    static CCriticalSection cs_totalBytesRecv;
    static CCriticalSection cs_totalBytesSent;
    static uint64_t nTotalBytesRecv;
    static uint64_t nTotalBytesSent;

    CNode(const CNode&);
    void operator=(const CNode&);

public:
    NodeId GetId() const { return id; }

    int32_t GetRefCount() {
        assert(nRefCount >= 0);
        return nRefCount;
    }

    // requires LOCK(cs_vRecvMsg)
    uint32_t GetTotalRecvSize() {
        uint32_t total = 0;
        for (const auto& msg : vRecvMsg)
            total += msg.vRecv.size() + 24;
        return total;
    }

    // requires LOCK(cs_vRecvMsg)
    bool ReceiveMsgBytes(const char* pch, uint32_t nBytes);

    // requires LOCK(cs_vRecvMsg)
    void SetRecvVersion(int32_t nVersionIn) {
        nRecvVersion = nVersionIn;
        for (auto& msg : vRecvMsg)
            msg.SetVersion(nVersionIn);
    }

    CNode* AddRef() {
        nRefCount++;
        return this;
    }

    void Release() { nRefCount--; }

    void AddAddressKnown(const CAddress& addr) { setAddrKnown.insert(addr); }

    void PushAddress(const CAddress& addr) {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (addr.IsValid() && !setAddrKnown.count(addr)) {
            if (vAddrToSend.size() >= MAX_ADDR_TO_SEND) {
                vAddrToSend[insecure_rand() % vAddrToSend.size()] = addr;
            } else {
                vAddrToSend.push_back(addr);
            }
        }
    }

    void AddInventoryKnown(const CInv& inv) {
        {
            LOCK(cs_inventory);
            setInventoryKnown.insert(inv);
        }
    }

    void PushInventory(const CInv& inv, bool forced = false) {
        {
            LOCK(cs_inventory);
            if (forced || !setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
        }
    }

    void AskFor(const CInv& inv) {
        if (mapAskFor.size() > MAPASKFOR_MAX_SZ) {
            return;
        }

        // We're using mapAskFor as a priority queue,
        // the key is the earliest time the request can be sent
        int64_t nRequestTime;
        limitedmap<CInv, int64_t>::const_iterator it = mapAlreadyAskedFor.find(inv);
        if (it != mapAlreadyAskedFor.end())
            nRequestTime = it->second;
        else
            nRequestTime = 0;
        LogPrint("net", "ask for %s %d (%s)\n", inv.ToString().c_str(), nRequestTime,
                 DateTimeStrFormat("%H:%M:%S", nRequestTime / 1000000).c_str());

        // Make sure not to reuse time indexes to keep things in the same order
        int64_t nNow = GetTimeMicros() - 1000000;
        static int64_t nLastTime;
        ++nLastTime;
        nNow      = max(nNow, nLastTime);
        nLastTime = nNow;

        // Each retry is 2 minutes after the last
        nRequestTime = max(nRequestTime + 2 * 60 * 1000000, nNow);
        if (it != mapAlreadyAskedFor.end())
            mapAlreadyAskedFor.update(it, nRequestTime);
        else
            mapAlreadyAskedFor.insert(make_pair(inv, nRequestTime));
        mapAskFor.insert(make_pair(nRequestTime, inv));
    }

    // TODO: Document the postcondition of this function.  Is cs_vSend locked?
    void BeginMessage(const char* pszCommand) EXCLUSIVE_LOCK_FUNCTION(cs_vSend) {
        ENTER_CRITICAL_SECTION(cs_vSend);
        assert(ssSend.size() == 0);
        ssSend << CMessageHeader(pszCommand, 0);
        LogPrint("net", "sending: %s\n", pszCommand);
    }

    // TODO: Document the precondition of this function.  Is cs_vSend locked?
    void AbortMessage() UNLOCK_FUNCTION(cs_vSend) {
        ssSend.clear();

        LEAVE_CRITICAL_SECTION(cs_vSend);

        LogPrint("net", "(aborted)\n");
    }

    // TODO: Document the precondition of this function.  Is cs_vSend locked?
    void EndMessage() UNLOCK_FUNCTION(cs_vSend) {
        // The -*messagestest options are intentionally not documented in the help message,
        // since they are only used during development to debug the networking code and are
        // not intended for end-users.
        if (SysCfg().IsArgCount("-dropmessagestest") && GetRand(SysCfg().GetArg("-dropmessagestest", 2)) == 0) {
            LogPrint("net", "dropmessages DROPPING SEND MESSAGE\n");
            AbortMessage();
            return;
        }
        if (SysCfg().IsArgCount("-fuzzmessagestest"))
            Fuzz(SysCfg().GetArg("-fuzzmessagestest", 10));

        if (ssSend.size() == 0)
            return;

        // Set the size
        uint32_t nSize = ssSend.size() - CMessageHeader::HEADER_SIZE;
        memcpy((char*)&ssSend[CMessageHeader::MESSAGE_SIZE_OFFSET], &nSize, sizeof(nSize));

        // Set the checksum
        uint256 hash           = Hash(ssSend.begin() + CMessageHeader::HEADER_SIZE, ssSend.end());
        uint32_t nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        assert(ssSend.size() >= CMessageHeader::CHECKSUM_OFFSET + sizeof(nChecksum));
        memcpy((char*)&ssSend[CMessageHeader::CHECKSUM_OFFSET], &nChecksum, sizeof(nChecksum));

        LogPrint("net", "(%d bytes)\n", nSize);

        deque<CSerializeData>::iterator it = vSendMsg.insert(vSendMsg.end(), CSerializeData());
        ssSend.GetAndClear(*it);
        nSendSize += (*it).size();

        // If write queue empty, attempt "optimistic write"
        if (it == vSendMsg.begin()) SocketSendData(this);

        LEAVE_CRITICAL_SECTION(cs_vSend);
    }

    void PushVersion();

    void PushMessage(const char* pszCommand) {
        try {
            BeginMessage(pszCommand);
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1>
    void PushMessage(const char* pszCommand, const T1& a1) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5,
                     const T6& a6) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5,
                     const T6& a6, const T7& a7) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5,
                     const T6& a6, const T7& a7, const T8& a8) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    template <typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8,
              typename T9>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5,
                     const T6& a6, const T7& a7, const T8& a8, const T9& a9) {
        try {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9;
            EndMessage();
        } catch (...) {
            AbortMessage();
            throw;
        }
    }

    bool IsSubscribed(uint32_t nChannel);
    void Subscribe(uint32_t nChannel, uint32_t nHops = 0);
    void CancelSubscribe(uint32_t nChannel);
    void CloseSocketDisconnect();
    void Cleanup();

    // Denial-of-service detection/prevention
    // The idea is to detect peers that are behaving
    // badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network
    // way.
    // IMPORTANT:  There should be nothing I can give a
    // node that it will forward on that will make that
    // node's peers drop it. If there is, an attacker
    // can isolate a node and/or try to split the network.
    // Dropping a node for sending stuff that is invalid
    // now but might be valid in a later version is also
    // dangerous, because it can cause a network split
    // between nodes running old code and nodes running
    // new code.
    static void ClearBanned();  // needed for unit testing
    static bool IsBanned(CNetAddr ip);
    static bool Ban(const CNetAddr& ip);
    void copyStats(CNodeStats& stats);

    // Network stats
    static void RecordBytesRecv(uint64_t bytes);
    static void RecordBytesSent(uint64_t bytes);

    static uint64_t GetTotalBytesRecv();
    static uint64_t GetTotalBytesSent();
};

void RelayTransaction(CBaseTx* pBaseTx, const uint256& hash);
void RelayTransaction(CBaseTx* pBaseTx, const uint256& hash, const CDataStream& ss);

/** Access to the (IP) address database (peers.dat) */
class CAddrDB {
private:
    boost::filesystem::path pathAddr;

public:
    CAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
};

#endif
