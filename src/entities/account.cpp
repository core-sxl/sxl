// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "account.h"
#include "config/configuration.h"
#include "config/const.h"
#include "main.h"


 uint64_t CAccount::GetBalance(const TokenSymbol &tokenSymbol, const BalanceType balanceType) {
     uint64_t ret = 0;
     if (GetBalance(tokenSymbol, balanceType, ret)) return ret;
     return 0;
 }

bool CAccount::GetBalance(const TokenSymbol &tokenSymbol, const BalanceType balanceType, uint64_t &value) {
    auto iter = tokens.find(tokenSymbol);
    if (iter != tokens.end()) {
        auto accountToken = iter->second;
        switch (balanceType) {
            case FREE_VALUE:    value = accountToken.free_amount;   return true;
            case STAKED_VALUE:  value = accountToken.staked_amount; return true;
            case FROZEN_VALUE:  value = accountToken.frozen_amount; return true;
            case VOTED_VALUE:   value = accountToken.voted_amount;  return true;
            default: return false;
        }
    }

    return false;
}

bool CAccount::OperateBalance(const TokenSymbol &tokenSymbol, const BalanceOpType opType, const uint64_t &value) {

    CAccountToken &accountToken = tokens[tokenSymbol];
    switch (opType) {
        case ADD_FREE: {
            accountToken.free_amount += value;
            return true;
        }
        case SUB_FREE: {
            if (accountToken.free_amount < value)
                return ERRORMSG("CAccount::OperateBalance, free_amount insufficient(%llu vs %llu) of %s",
                                accountToken.free_amount, value, tokenSymbol);

            accountToken.free_amount -= value;
            return true;
        }
        case STAKE: {
            if (accountToken.free_amount < value)
                return ERRORMSG("CAccount::OperateBalance, free_amount insufficient(%llu vs %llu) of %s",
                                accountToken.free_amount, value, tokenSymbol);

            accountToken.free_amount -= value;
            accountToken.staked_amount += value;
            return true;
        }
        case UNSTAKE: {
            if (accountToken.staked_amount < value)
                return ERRORMSG("CAccount::OperateBalance, staked_amount insufficient(%llu vs %llu) of %s",
                                accountToken.staked_amount, value, tokenSymbol);

            accountToken.free_amount += value;
            accountToken.staked_amount -= value;
            return true;
        }
        case FREEZE: {
            if (accountToken.free_amount < value)
                return ERRORMSG("CAccount::OperateBalance, free_amount insufficient(%llu vs %llu) of %s",
                                accountToken.free_amount, value, tokenSymbol);

            accountToken.free_amount -= value;
            accountToken.frozen_amount += value;
            return true;
        }
        case UNFREEZE: {
            if (accountToken.frozen_amount < value)
                return ERRORMSG("CAccount::OperateBalance, frozen_amount insufficient(%llu vs %llu) of %s",
                                accountToken.frozen_amount, value, tokenSymbol);

            accountToken.free_amount += value;
            accountToken.frozen_amount -= value;
            return true;
        }
        case VOTE: {
            if (accountToken.free_amount < value)
                return ERRORMSG("CAccount::OperateBalance, free_amount insufficient(%llu vs %llu) of %s",
                                accountToken.free_amount, value, tokenSymbol);

            accountToken.free_amount -= value;
            accountToken.voted_amount += value;
            return true;
        }
        case UNVOTE: {
            if (accountToken.voted_amount < value)
                return ERRORMSG("CAccount::OperateBalance, voted_amount insufficient(%llu vs %llu) of %s",
                                accountToken.voted_amount, value, tokenSymbol);

            accountToken.free_amount += value;
            accountToken.voted_amount -= value;
            return true;
        }
        default: return false;
    }
}

uint64_t CAccount::ComputeVoteBcoinInterest(const uint64_t lastVotedBcoins, const uint32_t currHeight) {
    if (lastVotedBcoins == 0) {
        return 0;  // 0 for the very 1st vote
    }

    uint64_t beginHeight = last_vote_height;
    uint64_t endHeight   = currHeight;
    uint8_t beginSubsidy = ::GetSubsidyRate(last_vote_height);
    uint8_t endSubsidy   = ::GetSubsidyRate(currHeight);

    auto ComputeInterest = [currHeight](const CRegID &regid, const uint64_t voteNum, const uint8_t subsidy,
                              const uint64_t beginHeight, const uint64_t endHeight,
                              const uint32_t yearHeight) -> uint64_t {
        uint64_t holdHeight = endHeight - beginHeight;
        uint64_t interest   = (long double)voteNum * holdHeight * subsidy / yearHeight / 100;

        LogPrint("profits",
                 "compute vote staking interest to voter: %s, current height: %u\n"
                 "interest = voteNum * (endHeight - beginHeight) * subsidy / yearHeight / 100\n"
                 "formula: %llu = 1.0 * %llu * (%llu - %llu) * %u / %u / 100\n",
                 regid.ToString(), currHeight, interest, voteNum, endHeight, beginHeight, subsidy, yearHeight);
        return interest;
    };

    uint32_t yearHeight = ::GetYearBlockCount();
    uint64_t interest   = 0;
    uint8_t subsidy     = beginSubsidy;
    while (subsidy != endSubsidy) {
        uint32_t jumpHeight = ::GetJumpHeightBySubsidy(subsidy - 1);
        interest += ComputeInterest(regid, lastVotedBcoins, subsidy, beginHeight, jumpHeight, yearHeight);
        beginHeight = jumpHeight;
        subsidy -= 1;
    }

    interest += ComputeInterest(regid, lastVotedBcoins, subsidy, beginHeight, endHeight, yearHeight);

    return interest;
}

CAccountToken CAccount::GetToken(const TokenSymbol &tokenSymbol) const {
    auto iter = tokens.find(tokenSymbol);
    if (iter != tokens.end())
        return iter->second;

    return CAccountToken();
}

bool CAccount::SetToken(const TokenSymbol &tokenSymbol, const CAccountToken &accountToken) {
    tokens[tokenSymbol] = accountToken;
    return true;
}

Object CAccount::ToJsonObj() const {
    vector<CCandidateReceivedVote> candidateVotes;
    pCdMan->pDelegateCache->GetCandidateVotes(regid, candidateVotes);

    Array candidateVoteArray;
    for (auto &vote : candidateVotes) {
        json_spirit::Object obj;

        CKeyID candidateKeyID;
        pCdMan->pAccountCache->GetKeyId(vote.candidate_uid, candidateKeyID);

        obj.push_back(json_spirit::Pair("candidate_uid",        vote.candidate_uid.ToJson()));
        obj.push_back(json_spirit::Pair("candidate_address",    candidateKeyID.ToAddress()));
        obj.push_back(json_spirit::Pair("candidate_votes",      vote.voted_num));

        candidateVoteArray.push_back(obj);
    }

    Object tokenMapObj;
    for (auto tokenPair : tokens) {
        Object tokenObj;
        const CAccountToken &token = tokenPair.second;
        tokenObj.push_back(Pair("free_amount",      token.free_amount));
        tokenObj.push_back(Pair("staked_amount",    token.staked_amount));
        tokenObj.push_back(Pair("frozen_amount",    token.frozen_amount));
        tokenObj.push_back(Pair("voted_amount",     token.voted_amount));

        tokenMapObj.push_back(Pair(tokenPair.first, tokenObj));
    }

    Object obj;
    obj.push_back(Pair("address",           keyid.ToAddress()));
    obj.push_back(Pair("keyid",             keyid.ToString()));
    obj.push_back(Pair("nickid",            nickid.ToString()));
    obj.push_back(Pair("regid",             regid.ToString()));
    obj.push_back(Pair("regid_mature",      regid.IsMature(chainActive.Height())));
    obj.push_back(Pair("owner_pubkey",      owner_pubkey.ToString()));
    obj.push_back(Pair("miner_pubkey",      miner_pubkey.ToString()));
    obj.push_back(Pair("tokens",            tokenMapObj));
    obj.push_back(Pair("received_votes",    received_votes));
    obj.push_back(Pair("vote_list",         candidateVoteArray));

    return obj;
}

string CAccount::ToString() const {
    string str;
    string  strTokens = "";
    for (auto pair : tokens) {
        CAccountToken &token = pair.second;
        strTokens += strprintf ("\n %s: {free=%llu, staked=%llu, frozen=%llu}\n",
                    pair.first, token.free_amount, token.staked_amount, token.frozen_amount);
    }
    str += strprintf(
        "regid=%s, keyid=%s, nickId=%s, owner_pubkey=%s, miner_pubkey=%s, "
        "tokens=%s, received_votes=%llu, last_vote_height=%llu\n",
        regid.ToString(), keyid.GetHex(), nickid.ToString(), owner_pubkey.ToString(), miner_pubkey.ToString(),
        strTokens, received_votes, last_vote_height);
    str += "candidate vote list: \n";

    vector<CCandidateReceivedVote> candidateVotes;
    pCdMan->pDelegateCache->GetCandidateVotes(regid, candidateVotes);
    for (auto & vote : candidateVotes) {
        str += vote.ToString();
    }

    return str;
}

bool CAccount::IsBcoinWithinRange(uint64_t nAddMoney) {
    if (!CheckBaseCoinRange(nAddMoney))
        return ERRORMSG("money:%lld larger than MaxMoney", nAddMoney);

    return true;
}

bool CAccount::ProcessCandidateVotes(const vector<CCandidateVote> &candidateVotesIn,
                                     vector<CCandidateReceivedVote> &candidateVotesInOut, const uint32_t currHeight,
                                     const uint32_t currBlockTime, const CAccountDBCache &accountCache,
                                     vector<CReceipt> &receipts) {
    if (currHeight < last_vote_height) {
        LogPrint("ERROR", "currHeight (%u) < last_vote_height (%llu)\n", currHeight, last_vote_height);
        return false;
    }

    uint64_t lastTotalVotes = GetToken(SYMB::SXL).voted_amount;

    for (const auto &vote : candidateVotesIn) {
        const CUserID &voteId = vote.GetCandidateUid();
        vector<CCandidateReceivedVote>::iterator itVote =
            find_if(candidateVotesInOut.begin(), candidateVotesInOut.end(),
                    [&voteId, &accountCache](const CCandidateReceivedVote &vote) {
                        if (voteId.type() != vote.GetCandidateUid().type()) {
                            CAccount account;
                            if (voteId.type() == typeid(CRegID)) {
                                accountCache.GetAccount(voteId, account);
                                return vote.GetCandidateUid() == account.owner_pubkey;

                            } else {  // vote.GetCandidateUid().type() == typeid(CPubKey)
                                accountCache.GetAccount(vote.GetCandidateUid(), account);
                                return account.owner_pubkey == voteId;
                            }
                        } else {
                            return vote.GetCandidateUid() == voteId;
                        }
                    });

        int32_t voteType = VoteType(vote.GetCandidateVoteType());
        if (INC_VOTE == voteType) {
            if (itVote != candidateVotesInOut.end()) { //existing vote
                uint64_t currVotes = itVote->GetVoteNum();

                if (!IsBcoinWithinRange(vote.GetVoteNum()))
                    return ERRORMSG("ProcessCandidateVotes() : oper fund value exceeds maximum ");

                itVote->SetVoteNum(currVotes + vote.GetVoteNum());

                if (!IsBcoinWithinRange(itVote->GetVoteNum()))
                    return ERRORMSG("ProcessCandidateVotes() : fund value exceeds maximum");

            } else {  // new vote
                if (candidateVotesInOut.size() == IniCfg().GetMaxVoteCandidateNum()) {
                    return ERRORMSG("ProcessCandidateVotes() : MaxVoteCandidateNum reached. Must revoke old votes 1st.");
                }

                candidateVotesInOut.push_back(vote);
            }
        } else if (DEC_VOTE == voteType) {
            if  (itVote != candidateVotesInOut.end()) { //existing vote
                uint64_t currVotes = itVote->GetVoteNum();

                if (!IsBcoinWithinRange(vote.GetVoteNum()))
                    return ERRORMSG("ProcessCandidateVotes() : oper fund value exceeds maximum ");

                if (itVote->GetVoteNum() < vote.GetVoteNum())
                    return ERRORMSG("ProcessCandidateVotes() : oper fund value exceeds delegate fund value");

                itVote->SetVoteNum(currVotes - vote.GetVoteNum());

                if (0 == itVote->GetVoteNum())
                    candidateVotesInOut.erase(itVote);

            } else {
                return ERRORMSG("ProcessCandidateVotes() : revocation votes not exist");
            }
        } else {
            return ERRORMSG("ProcessCandidateVotes() : operType: %d invalid", voteType);
        }
    }

    // sort account votes after the operations against the new votes
    std::sort(candidateVotesInOut.begin(), candidateVotesInOut.end(),
            [](CCandidateReceivedVote vote1, CCandidateReceivedVote vote2) {
        return vote1.GetVoteNum() > vote2.GetVoteNum();
    });

    uint64_t newTotalVotes = 0;
    if (!candidateVotesInOut.empty()) {
        for (const auto &vote : candidateVotesInOut) {
            newTotalVotes += vote.GetVoteNum();         // one bcoin one vote
        }
    }

    if (newTotalVotes > lastTotalVotes) {
        uint64_t addedVotes = newTotalVotes - lastTotalVotes;
        if (!OperateBalance(SYMB::SXL, BalanceOpType::VOTE, addedVotes)) {
            return ERRORMSG(
                "ProcessCandidateVotes() : delegate votes exceeds account bcoins when voting! "
                "newTotalVotes=%llu, lastTotalVotes=%llu, freeAmount=%llu",
                newTotalVotes, lastTotalVotes, GetToken(SYMB::SXL).free_amount);
        }
        receipts.emplace_back(regid, nullId, SYMB::SXL, addedVotes, ReceiptCode::DELEGATE_ADD_VOTE);
    } else if (newTotalVotes < lastTotalVotes) {
        uint64_t subVotes = lastTotalVotes - newTotalVotes;
        if (!OperateBalance(SYMB::SXL, BalanceOpType::UNVOTE, subVotes)) {
            return ERRORMSG(
                "ProcessCandidateVotes() : delegate votes insufficient to unvote! "
                "newTotalVotes=%llu, lastTotalVotes=%llu, freeAmount=%llu",
                newTotalVotes, lastTotalVotes, GetToken(SYMB::SXL).free_amount);
        }
        receipts.emplace_back(nullId, regid, SYMB::SXL, subVotes, ReceiptCode::DELEGATE_SUB_VOTE);
    } // else newTotalVotes == lastTotalVotes // do nothing

    // collect inflated bcoins or fcoins
    uint64_t bcoinAmountToInflate = ComputeVoteBcoinInterest(lastTotalVotes, currHeight);
    if (!IsBcoinWithinRange(bcoinAmountToInflate)) return false;

    if (!OperateBalance(SYMB::SXL, BalanceOpType::ADD_FREE, bcoinAmountToInflate)) {
        return ERRORMSG("ProcessCandidateVotes() : add bcoins to inflate failed");
    }
    receipts.emplace_back(nullId, regid, SYMB::SXL, bcoinAmountToInflate,
                          ReceiptCode::DELEGATE_VOTE_INTEREST);

    LogPrint("profits", "Account(%s) received vote staking interest amount (bcoins): %llu\n",
             regid.ToString(), bcoinAmountToInflate);

    // Attention: update last vote height/last vote epoch after computing vote staking interest.
    last_vote_height = currHeight;
    last_vote_epoch  = currBlockTime;

    return true;
}

bool CAccount::StakeVoteBcoins(VoteType type, const uint64_t votes) {
    switch (type) {
        case INC_VOTE: {
            received_votes += votes;
            if (!IsBcoinWithinRange(received_votes)) {
                return ERRORMSG("StakeVoteBcoins() : delegates total votes exceed maximum ");
            }

            break;
        }

        case DEC_VOTE: {
            if (received_votes < votes) {
                return ERRORMSG("StakeVoteBcoins() : delegates total votes less than revocation vote number");
            }
            received_votes -= votes;

            break;
        }

        default:
            return ERRORMSG("StakeVoteBcoins() : unexpected type");
    }

    return true;
}

bool CAccount::IsMyUid(const CUserID &uid) {
    if (uid.type() == typeid(CKeyID)) {
        return keyid == uid.get<CKeyID>();
    } else if (uid.type() == typeid(CRegID)) {
        return !regid.IsEmpty() && regid == uid.get<CRegID>();
    } else if (uid.type() == typeid(CPubKey)) {
        return owner_pubkey.IsValid() && owner_pubkey == uid.get<CPubKey>();
    }
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// class CVmOperate

Object CVmOperate::ToJson() {
    Object obj;
    if (accountType == AccountType::REGID) {
        vector<uint8_t> vRegId(accountId, accountId + 6);
        CRegID regId(vRegId);
        obj.push_back(Pair("regid", regId.ToString()));
    } else if (accountType == AccountType::BASE58ADDR) {
        string addr(accountId, accountId + sizeof(accountId));
        obj.push_back(Pair("addr", addr));
    }
    obj.push_back(Pair("opertype", GetBalanceOpTypeName((BalanceOpType)opType)));
    if (timeoutHeight > 0)
        obj.push_back(Pair("timeoutHeight", (int32_t)timeoutHeight));

    uint64_t amount;
    memcpy(&amount, money, sizeof(money));
    obj.push_back(Pair("amount", amount));
    return obj;
}
