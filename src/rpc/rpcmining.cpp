// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "commons/json/json_spirit_utils.h"
#include "commons/json/json_spirit_value.h"
#include "commons/serialize.h"
#include "commons/uint256.h"
#include "commons/util.h"
#include "config/chainparams.h"
#include "config/version.h"
#include "init.h"
#include "main.h"
#include "miner/miner.h"
#include "rpc/core/rpcprotocol.h"
#include "rpc/core/rpcserver.h"
#include "sync.h"
#include "tx/txmempool.h"
#include "wallet/wallet.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace json_spirit;
using namespace std;

Value setgenerate(const Array& params, bool fHelp) {
    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw runtime_error(
            "setgenerate generate ( genblocklimit )\n"
            "\nSet 'generate' true or false to turn generation on or off.\n"
            "Generation is limited to 'genblocklimit' processors, -1 is unlimited.\n"
            "See the getgenerate call for the current setting.\n"
            "\nArguments:\n"
            "1. generate            (boolean, required) Set to true to turn on generation, off to turn off.\n"
            "2. genblocklimit       (numeric, optional) Set the processor limit for when generation is on. Can be -1 for "
            "unlimited.\n"
            "                    Note: in -regtest mode, genblocklimit controls how many blocks are generated "
            "immediately.\n"
            "\nExamples:\n"
            "\nSet the generation on with a limit of one processor\n" +
            HelpExampleCli("setgenerate", "true 1") + "\nAs json rpc call\n" +
            HelpExampleRpc("setgenerate", "true, 1") + "\nTurn off generation\n" +
            HelpExampleCli("setgenerate", "false") + "\nAs json rpc call\n" + HelpExampleRpc("setgenerate", "false"));

    static bool fGenerate = false;

    set<CKeyID> setKeyId;
    setKeyId.clear();
    pWalletMain->GetKeys(setKeyId, true);

    bool bSetEmpty(true);
    for (auto & keyId : setKeyId) {
        CUserID userId(keyId);
        CAccount acctInfo;
        if (pCdMan->pAccountCache->GetAccount(userId, acctInfo)) {
            bSetEmpty = false;
            break;
        }
    }

    if (bSetEmpty)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No key for mining");

    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    int genBlockLimit = 1;
    if (params.size() == 2) {
        genBlockLimit = params[1].get_int();
        if(genBlockLimit <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid genblocklimit");
        }
    }
    Object obj;
    if (fGenerate == false){
        GenerateCoinBlock(false, pWalletMain, 1);

        obj.push_back(Pair("msg", "stoping  mining"));
        return obj;
    }

    GenerateCoinBlock(true, pWalletMain, genBlockLimit);
    obj.push_back(Pair("msg", "in  mining"));
    return obj;
}