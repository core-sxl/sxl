// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ENTITIES_VOTE_H
#define ENTITIES_VOTE_H

#include <boost/variant.hpp>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "commons/json/json_spirit_utils.h"
#include "commons/json/json_spirit_value.h"
#include "key.h"
#include "crypto/hash.h"
#include "entities/id.h"

enum VoteType : uint8_t {
    NULL_VOTE   = 0,  //!< invalid vote operate
    INC_VOTE   = 1,  //!< add operate
    DEC_VOTE = 2,  //!< minus operate
};

static const unordered_map<uint8_t, string> kVoteTypeMap = {
    { NULL_VOTE,    "NULL_VOTE"     },
    { INC_VOTE,     "INC_VOTE"     },
    { DEC_VOTE,     "DEC_VOTE"   },
};

class CCandidateVote {
public:
    uint8_t voteType;        //!< 1:INC_VOTE 2:DEC_VOTE
    CUserID candidateUid;    //!< candidate RegId or PubKey
    uint64_t voteNum;        //!< count of votes to the candidate

    mutable uint256 sigHash;  //!< only in memory

public:
    CCandidateVote() {
        voteType     = NULL_VOTE;
        candidateUid = CUserID();
        voteNum      = 0;
    }
    CCandidateVote(VoteType voteTypeIn, CUserID voteUserIdIn, uint64_t voteNumIn) {
        voteType     = voteTypeIn;
        candidateUid = voteUserIdIn;
        voteNum      = voteNumIn;
    }
    CCandidateVote(const CCandidateVote &voteIn) {
        voteType     = voteIn.voteType;
        candidateUid = voteIn.candidateUid;
        voteNum      = voteIn.voteNum;
    }
    CCandidateVote &operator=(const CCandidateVote &voteIn) {
        if (this == &voteIn)
            return *this;

        this->voteType     = voteIn.voteType;
        this->candidateUid = voteIn.candidateUid;
        this->voteNum      = voteIn.voteNum;

        return *this;
    }
    ~CCandidateVote() {}

    uint256 GetHash(bool recalculate = false) const {
        if (recalculate || sigHash.IsNull()) {
            CHashWriter ss(SER_GETHASH, 0);

            ss << voteType << candidateUid << VARINT(voteNum);
            sigHash = ss.GetHash();
        }

        return sigHash;
    }

    friend bool operator<(const CCandidateVote &fa, const CCandidateVote &fb) {
        return (fa.voteNum <= fb.voteNum);
    }
    friend bool operator>(const CCandidateVote &fa, const CCandidateVote &fb) {
        return !operator<(fa, fb);
    }
    friend bool operator==(const CCandidateVote &fa, const CCandidateVote &fb) {
        return (fa.candidateUid == fb.candidateUid && fa.voteNum == fb.voteNum);
    }

    IMPLEMENT_SERIALIZE(
        READWRITE(voteType);
        READWRITE(candidateUid);
        READWRITE(VARINT(voteNum));
    );

    const CUserID &GetCandidateUid() const { return candidateUid; }
    unsigned char GetCandidateVoteType() const { return voteType; }
    uint64_t GetVoteNum() const { return voteNum; }
    void SetVoteNum(uint64_t voteNumIn) { voteNum = voteNumIn; }
    void SetCandidateUid(const CUserID &votedUserIdIn) { candidateUid = votedUserIdIn; }

    json_spirit::Object ToJson() const {
        json_spirit::Object obj;

        obj.push_back(json_spirit::Pair("vote_type",        GetVoteType(voteType)));
        obj.push_back(json_spirit::Pair("candidate_uid",    candidateUid.ToJson()));
        obj.push_back(json_spirit::Pair("candidate_votes",  voteNum));

        return obj;
    }

    string ToString() const {
        return strprintf("voteType: %s, candidateUid: %s, candidateVotes: %lld\n", GetVoteType(voteType),
                         candidateUid.ToString(), voteNum);
    }

private:
    static string GetVoteType(const unsigned char voteTypeIn) {
        auto it = kVoteTypeMap.find(voteTypeIn);
        if (it != kVoteTypeMap.end())
            return it->second;
        else
            return "";
    }
};


class CCandidateReceivedVote {
public:
    CUserID candidate_uid;  //!< candidate RegId or PubKey
    uint64_t voted_num;     //!< count of votes to the candidate

public:
    CCandidateReceivedVote() {};

    CCandidateReceivedVote(const CCandidateVote &vote):
        candidate_uid(vote.GetCandidateUid()),
        voted_num(vote.GetVoteNum()) { };

public:
    friend bool operator<(const CCandidateReceivedVote &fa, const CCandidateReceivedVote &fb) {
        return (fa.voted_num <= fb.voted_num);
    }
    friend bool operator>(const CCandidateReceivedVote &fa, const CCandidateReceivedVote &fb) {
        return !operator<(fa, fb);
    }
    friend bool operator==(const CCandidateReceivedVote &fa, const CCandidateReceivedVote &fb) {
        return (fa.candidate_uid == fb.candidate_uid && fa.voted_num == fb.voted_num);
    }

    IMPLEMENT_SERIALIZE(
        READWRITE(candidate_uid);
        READWRITE(VARINT(voted_num));
    );

     json_spirit::Object ToJson() const {
        json_spirit::Object obj;

        obj.push_back(json_spirit::Pair("candidate_uid",    candidate_uid.ToJson()));
        obj.push_back(json_spirit::Pair("candidate_votes",  voted_num));

        return obj;
    }

    string ToString() const {
        string str = strprintf("candidate_uid: %s, candidate_votes: %lld \n", candidate_uid.ToString(), voted_num);
        return str;
    }

    const CUserID &GetCandidateUid() const { return candidate_uid; }
    uint64_t GetVoteNum() const { return voted_num; }
    void SetVoteNum(uint64_t voteNumIn) { voted_num = voteNumIn; }
};

#endif //ENTITIES_VOTE_H