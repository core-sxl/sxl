// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "delegatetx.h"

#include "commons/serialize.h"
#include "tx.h"
#include "crypto/hash.h"
#include "commons/util.h"
#include "main.h"
#include "vm/luavm/luavmrunenv.h"
#include "miner/miner.h"
#include "config/version.h"

bool CDelegateVoteTx::CheckTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    IMPLEMENT_CHECK_TX_FEE;
    IMPLEMENT_CHECK_TX_REGID_OR_PUBKEY(txUid.type());

    if (candidateVotes.empty() || candidateVotes.size() > IniCfg().GetMaxVoteCandidateNum()) {
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::CheckTx, candidate votes out of range"), REJECT_INVALID,
                         "candidate-votes-out-of-range");
    }

    if ((txUid.type() == typeid(CPubKey)) && !txUid.get<CPubKey>().IsFullyValid())
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::CheckTx, public key is invalid"), REJECT_INVALID,
                        "bad-publickey");

    CAccount srcAccount;
    if (!cw.accountCache.GetAccount(txUid, srcAccount)) {
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::CheckTx, get account info error, uid=%s", txUid.ToString()),
                         REJECT_INVALID, "bad-read-accountdb");
    }

    for (const auto &vote : candidateVotes) {
        IMPLEMENT_CHECK_TX_CANDIDATE_REGID(vote.GetCandidateUid().type());

        if (0 >= vote.GetVoteNum() || (uint64_t)GetBaseCoinMaxMoney() < vote.GetVoteNum())
            return ERRORMSG("CDelegateVoteTx::CheckTx, votes: %lld not within (0 .. MaxVote)", vote.GetVoteNum());

        CAccount candidateAcct;
        if (!cw.accountCache.GetAccount(vote.GetCandidateUid(), candidateAcct))
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::CheckTx, get account info error, address=%s",
                             vote.GetCandidateUid().ToString()), REJECT_INVALID, "bad-read-accountdb");

        if (!candidateAcct.HaveOwnerPubKey()) {
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::CheckTx, account is unregistered, address=%s",
                             vote.GetCandidateUid().ToString()), REJECT_INVALID, "bad-read-accountdb");
        }
    }

    CPubKey pubKey = (txUid.type() == typeid(CPubKey) ? txUid.get<CPubKey>() : srcAccount.owner_pubkey);
    IMPLEMENT_CHECK_TX_SIGNATURE(pubKey);

    return true;
}

bool CDelegateVoteTx::ExecuteTx(CTxExecuteContext &context) {
    CCacheWrapper &cw       = *context.pCw;
    CValidationState &state = *context.pState;

    CAccount srcAccount;
    if (!cw.accountCache.GetAccount(txUid, srcAccount)) {
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, read account info error"), UPDATE_ACCOUNT_FAIL,
                         "bad-read-accountdb");
    }

    if (!GenerateRegID(context, srcAccount)) {
        return false;
    }

    if (!srcAccount.OperateBalance(SYMB::SXL, SUB_FREE, llFees)) {
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, operate account failed, txUid=%s",
                        txUid.ToString()), UPDATE_ACCOUNT_FAIL, "operate-account-failed");
    }

    vector<CCandidateReceivedVote> candidateVotesInOut;
    CRegID &regId = srcAccount.regid;
    cw.delegateCache.GetCandidateVotes(regId, candidateVotesInOut);

    vector<CReceipt> receipts;
    if (!srcAccount.ProcessCandidateVotes(candidateVotes, candidateVotesInOut, context.height, context.block_time,
                                          cw.accountCache, receipts)) {
        return state.DoS(
            100, ERRORMSG("CDelegateVoteTx::ExecuteTx, operate candidate votes failed, txUid=%s", txUid.ToString()),
            OPERATE_CANDIDATE_VOTES_FAIL, "operate-candidate-votes-failed");
    }
    if (!cw.delegateCache.SetCandidateVotes(regId, candidateVotesInOut)) {
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, write candidate votes failed, txUid=%s", txUid.ToString()),
                        WRITE_CANDIDATE_VOTES_FAIL, "write-candidate-votes-failed");
    }

    if (!cw.accountCache.SaveAccount(srcAccount)) {
        return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, save account info error"), UPDATE_ACCOUNT_FAIL,
                         "bad-save-accountdb");
    }

    for (const auto &vote : candidateVotes) {
        CAccount delegateAcct;
        const CUserID &delegateUId = vote.GetCandidateUid();
        if (!cw.accountCache.GetAccount(delegateUId, delegateAcct)) {
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, read account id %s account info error",
                            delegateUId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-read-accountdb");
        }
        uint64_t oldVotes = delegateAcct.received_votes;
        if (!delegateAcct.StakeVoteBcoins(VoteType(vote.GetCandidateVoteType()), vote.GetVoteNum())) {
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, operate account id %s vote fund error",
                            delegateUId.ToString()), UPDATE_ACCOUNT_FAIL, "operate-vote-error");
        }

        // Votes: set the new value and erase the old value
        if (!cw.delegateCache.SetDelegateVotes(delegateAcct.regid, delegateAcct.received_votes)) {
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, save account id %s vote info error",
                            delegateUId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-save-delegatedb");
        }

        if (!cw.delegateCache.EraseDelegateVotes(delegateAcct.regid, oldVotes)) {
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, erase account id %s vote info error",
                            delegateUId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-save-delegatedb");
        }

        if (!cw.accountCache.SaveAccount(delegateAcct)) {
            return state.DoS(100, ERRORMSG("CDelegateVoteTx::ExecuteTx, save account id %s info error",
                            delegateUId.ToString()), UPDATE_ACCOUNT_FAIL, "bad-save-accountdb");
        }
    }

    cw.txReceiptCache.SetTxReceipts(GetHash(), receipts);

    return true;
}

string CDelegateVoteTx::ToString(CAccountDBCache &accountCache) {
    string str;

    str += strprintf("txType=%s, hash=%s, ver=%d, txUid=%s, llFees=%llu, valid_height=%d", GetTxType(nTxType),
                     GetHash().ToString(), nVersion, txUid.ToString(), llFees, valid_height);
    str += "vote: ";
    for (const auto &vote : candidateVotes) {
        str += strprintf("%s", vote.ToString());
    }

    return str;
}

Object CDelegateVoteTx::ToJson(const CAccountDBCache &accountCache) const {
    Object result = CBaseTx::ToJson(accountCache);

    Array candidateVoteArray;
    for (const auto &vote : candidateVotes) {
        json_spirit::Object obj;

        const auto &voteJson = vote.ToJson();
        obj.assign(voteJson.begin(), voteJson.end());

        CKeyID candidateKeyID;
        accountCache.GetKeyId(vote.candidateUid, candidateKeyID);
        obj.push_back(json_spirit::Pair("candidate_address", candidateKeyID.ToAddress()));

        candidateVoteArray.push_back(obj);
    }

    result.push_back(Pair("candidate_votes",    candidateVoteArray));
    return result;
}
