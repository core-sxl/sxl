// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block.h"

#include "entities/account.h"
#include "main.h"
#include "net.h"

uint256 CBlockHeader::GetHash() const {
    return ComputeSignatureHash();
}

void CBlockHeader::SetHeight(uint32_t  height) {
    this->height = height;
}

uint256 CBlockHeader::ComputeSignatureHash() const {
    CHashWriter ss(SER_GETHASH, CLIENT_VERSION);
    ss << nVersion << prevBlockHash << merkleRootHash << nTime << height << nFuel << nFuelRate;
    return ss.GetHash();
}

uint256 CBlock::BuildMerkleTree() const {
    vMerkleTree.clear();
    for (const auto& ptx : vptx) {
        vMerkleTree.push_back(ptx->GetHash());
    }

    int32_t j = 0;
    for (int32_t nSize = vptx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
        for (int32_t i = 0; i < nSize; i += 2) {
            int32_t i2 = min(i + 1, nSize - 1);
            vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j + i]), END(vMerkleTree[j + i]),
                                       BEGIN(vMerkleTree[j + i2]), END(vMerkleTree[j + i2])));
        }
        j += nSize;
    }

    return (vMerkleTree.empty() ? uint256() : vMerkleTree.back());
}

vector<uint256> CBlock::GetMerkleBranch(int32_t index) const {
    if (vMerkleTree.empty())
        BuildMerkleTree();

    vector<uint256> vMerkleBranch;
    int32_t j = 0;
    for (int32_t nSize = vptx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
        int32_t i = min(index ^ 1, nSize - 1);
        vMerkleBranch.push_back(vMerkleTree[j + i]);
        index >>= 1;
        j += nSize;
    }

    return vMerkleBranch;
}

uint256 CBlock::CheckMerkleBranch(uint256 hash, const vector<uint256>& vMerkleBranch, int32_t index) {
    if (index == -1)
        return uint256();

    for (const auto& otherside : vMerkleBranch) {
        if (index & 1)
            hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
        index >>= 1;
    }

    return hash;
}

CUserID CBlock::GetMinerUserID() const {
    assert(vptx.size() > 0);
    assert(vptx[0]->IsBlockRewardTx());

    return vptx[0]->txUid;
}

void CBlock::Print() const {
    LogPrint("DEBUG",
             "block height=%d, hash=%s, ver=%d, hashPrevBlock=%s, merkleRootHash=%s, nTime=%u, vtx=%u, nFuel=%d, "
             "nFuelRate=%d, median prices: %s\n",
             height, GetHash().ToString(), nVersion, prevBlockHash.ToString(), merkleRootHash.ToString(), nTime,
             vptx.size(), nFuel, nFuelRate);
}

std::tuple<bool, int> CBlock::GetTxIndex(const uint256& txid) const {
    for (size_t i = 0; i < vMerkleTree.size(); i++) {
        if (txid == vMerkleTree[i]) {
            return std::make_tuple(true, i);
        }
    }

    return std::make_tuple(false, 0);
}
