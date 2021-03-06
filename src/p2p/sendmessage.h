// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SENDMESSAGE_H
#define SENDMESSAGE_H

#include "main.h"

// Requires cs_mapNodeState.
void MarkBlockAsInFlight(const uint256 &hash, NodeId nodeId) {
    AssertLockHeld(cs_mapNodeState);
    CNodeState *state = State(nodeId);
    assert(state != nullptr);

    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    QueuedBlock newentry = {hash, GetTimeMicros(), state->nBlocksInFlight};
    if (state->nBlocksInFlight == 0)
        state->nLastBlockReceive = newentry.nTime;  // Reset when a first request is sent.

    list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(), newentry);
    state->nBlocksInFlight++;
    mapBlocksInFlight[hash] = std::make_tuple(nodeId, it, GetTimeMicros());
}

bool SendMessages(CNode *pTo, bool fSendTrickle) {
    {
        // Don't send anything until we get their version message
        if (pTo->nVersion == 0)
            return true;

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pTo->fPingQueued) {
            // RPC ping request by user
            pingSend = true;
        }

        if (pTo->nLastSend && GetTime() - pTo->nLastSend > 30 * 60 && pTo->vSendMsg.empty()) {
            // Ping automatically sent as a keepalive
            pingSend = true;
        }

        if (pingSend) {
            uint64_t nonce = 0;
            while (nonce == 0) {
                RAND_bytes((uint8_t *)&nonce, sizeof(nonce));
            }

            pTo->nPingNonceSent = nonce;
            pTo->fPingQueued    = false;
            // if (pTo->nVersion > BIP0031_VERSION) {
            // Take timestamp as close as possible before transmitting ping
            pTo->nPingUsecStart = GetTimeMicros();
            pTo->PushMessage("ping", nonce);
            // } else {
            //     // Peer is too old to support ping command with nonce, pong will never arrive, disable timing
            //     pTo->nPingUsecStart = 0;
            //     pTo->PushMessage("ping");
            // }
        }

        {
            TRY_LOCK(cs_main, lockMain);  // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
            if (!lockMain)
                return true;

            // Address refresh broadcast
            static int64_t nLastRebroadcast;
            if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60)) {
                {
                    LOCK(cs_vNodes);
                    for (auto pNode : vNodes) {
                        // Periodically clear setAddrKnown to allow refresh broadcasts
                        if (nLastRebroadcast)
                            pNode->setAddrKnown.clear();

                        // Rebroadcast our address
                        if (!fNoListen) {
                            CAddress addr = GetLocalAddress(&pNode->addr);
                            if (addr.IsRoutable())
                                pNode->PushAddress(addr);
                        }
                    }
                }
                nLastRebroadcast = GetTime();
            }

            //
            // Message: addr
            //
            if (fSendTrickle) {
                vector<CAddress> vAddr;
                vAddr.reserve(pTo->vAddrToSend.size());
                for (const auto &addr : pTo->vAddrToSend) {
                    // returns true if wasn't already contained in the set
                    if (pTo->setAddrKnown.insert(addr).second) {
                        vAddr.push_back(addr);
                        // receiver rejects addr messages larger than 1000
                        if (vAddr.size() >= 1000) {
                            pTo->PushMessage("addr", vAddr);
                            vAddr.clear();
                        }
                    }
                }
                pTo->vAddrToSend.clear();
                if (!vAddr.empty())
                    pTo->PushMessage("addr", vAddr);
            }

            // Start block sync
            if (pTo->fStartSync && !SysCfg().IsImporting() && !SysCfg().IsReindex()) {
                pTo->fStartSync = false;
                nSyncTipHeight  = pTo->nStartingHeight;
                LogPrint("net", "start block sync lead to getblocks\n");
                PushGetBlocks(pTo, chainActive.Tip(), uint256());
            }
        }

        LOCK(cs_mapNodeState);
        CNodeState &state = *State(pTo->GetId());
        if (state.fShouldBan) {
            if (pTo->addr.IsLocal()) {
                LogPrint("INFO", "Warning: not banning local node %s!\n", pTo->addr.ToString());
            }
            else {
                LogPrint("INFO", "Warning: banned a remote node %s!\n", pTo->addr.ToString());
                pTo->fDisconnect = true;
                CNode::Ban(pTo->addr);
            }
            state.fShouldBan = false;
        }

        for (const auto &reject : state.rejects)
            pTo->PushMessage("reject", (string) "block", reject.chRejectCode, reject.strRejectReason, reject.blockHash);
        state.rejects.clear();

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pTo->cs_inventory);
            vInv.reserve(pTo->vInventoryToSend.size());
            vInvWait.reserve(pTo->vInventoryToSend.size());
            for (const auto &inv : pTo->vInventoryToSend) {
                if (pTo->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle) {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt.IsNull())
                        hashSalt = GetRandHash();
                    uint256 hashRand  = ArithToUint256(UintToArith256(inv.hash) ^ UintToArith256(hashSalt));
                    hashRand          = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((UintToArith256(hashRand) & 3) != 0);

                    if (fTrickleWait) {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pTo->setInventoryKnown.insert(inv).second) {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000) {
                        pTo->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pTo->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pTo->PushMessage("inv", vInv);

        // Detect stalled peers. Require that blocks are in flight, we haven't
        // received a (requested) block in one minute, and that all blocks are
        // in flight for over two minutes, since we first had a chance to
        // process an incoming block.
        int64_t nNow = GetTimeMicros();
        if (!pTo->fDisconnect && state.nBlocksInFlight &&
            state.nLastBlockReceive < state.nLastBlockProcess - BLOCK_DOWNLOAD_TIMEOUT * 1000000 &&
            state.vBlocksInFlight.front().nTime < state.nLastBlockProcess - 2 * BLOCK_DOWNLOAD_TIMEOUT * 1000000) {
            LogPrint("INFO", "Peer %s is stalling block download, disconnecting\n", state.name.c_str());
            pTo->fDisconnect = true;
        }

        //
        // Message: getdata (blocks)
        //
        vector<CInv> vGetData;
        int32_t index = 0;
        while (!pTo->fDisconnect && state.nBlocksToDownload && state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            uint256 hash = state.vBlocksToDownload.front();
            vGetData.push_back(CInv(MSG_BLOCK, hash));
            MarkBlockAsInFlight(hash, pTo->GetId());
            LogPrint("net", "send MSG_BLOCK msg! time_ms=%lld, hash=%s, peer=%s, FlightBlocks=%d, index=%d\n",
                GetTimeMillis(), hash.ToString(), state.name, state.nBlocksInFlight, index++);
            if (vGetData.size() >= 1000) {
                pTo->PushMessage("getdata", vGetData);
                vGetData.clear();
                index = 0;
            }
        }

        //
        // Message: getdata (non-blocks)
        //
        while (!pTo->fDisconnect && !pTo->mapAskFor.empty() && (*pTo->mapAskFor.begin()).first <= nNow) {
            const CInv &inv = (*pTo->mapAskFor.begin()).second;
            if (!AlreadyHave(inv)) {
                LogPrint("net", "sending getdata: %s\n", inv.ToString());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000) {
                    pTo->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            pTo->mapAskFor.erase(pTo->mapAskFor.begin());
        }

        if (!vGetData.empty())
            pTo->PushMessage("getdata", vGetData);
    }

    return true;
}

#endif