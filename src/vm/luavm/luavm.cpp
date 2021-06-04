// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "luavm.h"

#include "crypto/hash.h"
#include "entities/key.h"
#include "lua/lua.hpp"
#include "luavmrunenv.h"
#include "main.h"
#include "tx/tx.h"

#include <openssl/des.h>

#include <cassert>
#include <cstring>
#include <vector>

using namespace std;

CLuaVM::CLuaVM(const string &codeIn, const string &argumentsIn):
    code(codeIn), arguments(argumentsIn) {
    assert(code.size() <= MAX_CONTRACT_CODE_SIZE);
    assert(arguments.size() <= MAX_CONTRACT_ARGUMENT_SIZE);
}

CLuaVM::~CLuaVM() {}

#ifdef WIN_DLL
extern "C" __declspec(dllexport) int luaopen_mylib(lua_State *L);
#else
LUAMOD_API int luaopen_mylib(lua_State *L);
#endif

bool InitLuaLibsEx(lua_State *L);

void vm_openlibs(lua_State *L) {
    static const luaL_Reg lualibs[] = {
        {"base", luaopen_base},
        {LUA_TABLIBNAME, luaopen_table},  {LUA_MATHLIBNAME, luaopen_math},
        {LUA_STRLIBNAME, luaopen_string}, {NULL, NULL}};

    const luaL_Reg *lib;
    for (lib = lualibs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1); /* remove lib */
    }
}

tuple<bool, string> CLuaVM::CheckScriptSyntax(const char *filePath) {

    std::unique_ptr<lua_State, decltype(&lua_close)> lua_state_ptr(luaL_newstate(), &lua_close);
    if (!lua_state_ptr) {
        LogPrint("vm", "CLuaVM::CheckScriptSyntax luaL_newstate() failed\n");
        return std::make_tuple(false, string("CLuaVM::CheckScriptSyntax luaL_newstate() failed\n"));
    }
    lua_State *lua_state = lua_state_ptr.get();
    vm_openlibs(lua_state);

    if (!InitLuaLibsEx(lua_state)) {
        LogPrint("vm", "CLuaVM::CheckScriptSyntax InitLuaLibsEx error\n");
        return std::make_tuple(-1, string("CLuaVM::CheckScriptSyntax InitLuaLibsEx error\n"));
    }

    luaL_requiref(lua_state, "mylib", luaopen_mylib, 1);

    int nRet = luaL_loadfile(lua_state, filePath);
    if (nRet) {
        const char *errStr = lua_tostring(lua_state, -1);
        return std::make_tuple(false, string(errStr));
    }

    return std::make_tuple(true, string("OK"));
}

static void ReportBurnState(lua_State *L, CLuaVMRunEnv *pVmRunEnv) {
    lua_burner_state *burnerState = lua_GetBurnerState(L);
    LogPrint("vm", "contract run info: txid=%s,"
             " version=%d,"
             " fuelLimit=%lld,"
             " burnedFuel=%lld,"
             " fuelStep=%lld,"
             " fuelRefund=%lld,"
             " allocMemSize=%llu,"
             " fuelMem=%llu,"
             " fuelOperator=%llu,"
             " fuelStore=%llu,"
             " fuelAccount=%llu"
             " fuelFunction=%llu\n",
             pVmRunEnv->GetCurTxHash().ToString(),
             burnerState->version,
             burnerState->fuelLimit,
             lua_GetBurnedFuel(L),
             burnerState->fuelStep,
             burnerState->fuelRefund,
             burnerState->allocMemSize,
             lua_GetMemoryFuel(L),
             burnerState->fuelOperator,
             burnerState->fuelStore,
             burnerState->fuelAccount,
             burnerState->fuelFunction
    );
}

static string GetLuaError(lua_State *L, int status, string prefix) {
    string ret;
    if (status != LUA_OK) {
        const char *errStr = lua_tostring(L, -1);
        if (errStr == NULL) {
            errStr = "unknown";
        }

        ret = prefix + ": " + errStr;
        if (status == LUA_ERR_BURNEDOUT) {
            ret += ". Need more fuel to burn";
        }
    }

    return ret;
}

tuple<uint64_t, string> CLuaVM::Run(uint64_t fuelLimit, CLuaVMRunEnv *pVmRunEnv) {
    if (NULL == pVmRunEnv) {
        return std::make_tuple(-1, string("pVmRunEnv == NULL"));
    }

    // 1. initialize lua run env
    std::unique_ptr<lua_State, decltype(&lua_close)> lua_state_ptr(luaL_newstate(), &lua_close);
    if (!lua_state_ptr) {
        LogPrint("vm", "CLuaVM::Run luaL_newstate() failed\n");
        return std::make_tuple(-1, string("CLuaVM::Run luaL_newstate() failed"));
    }

    lua_State *lua_state = lua_state_ptr.get();

    if (!lua_StartBurner(lua_state, pVmRunEnv, fuelLimit, pVmRunEnv->GetBurnVersion())) {
        LogPrint("vm", "CLuaVM::Run lua_StartBurner() failed\n");
        return std::make_tuple(-1, string("CLuaVM::Run lua_StartBurner() failed"));
    }

    // 2. open libs
    vm_openlibs(lua_state);

    if (!InitLuaLibsEx(lua_state)) {
        LogPrint("vm", "InitLuaLibsEx error\n");
        return std::make_tuple(-1, string("InitLuaLibsEx error"));
    }

    // 3. register mylib
    luaL_requiref(lua_state, "mylib", luaopen_mylib, 1);

    // 4. push contract arguments
    lua_newtable(lua_state);
    lua_pushnumber(lua_state, -1);
    lua_rawseti(lua_state, -2, 0);

    for (size_t i = 0; i < arguments.size(); i++) {
        lua_pushinteger(lua_state, (uint8_t)arguments[i]);
        lua_rawseti(lua_state, -2, i + 1);
    }

    lua_setglobal(lua_state, "contract");

    lua_pushlightuserdata(lua_state, pVmRunEnv);
    lua_setglobal(lua_state, "pVmRunEnv");
    LogPrint("vm", "pVmRunEnv=%p\n", pVmRunEnv);

    // 5. load contract
    string strError;
    int32_t luaStatus = luaL_loadbuffer(lua_state, code.c_str(), code.size(), "line");
    if (luaStatus == LUA_OK) {
        luaStatus = lua_pcallk(lua_state, 0, 0, 0, 0, NULL, BURN_VER_STEP_V1);
        if (luaStatus != LUA_OK) {
            strError = GetLuaError(lua_state, luaStatus, "lua_pcallk failed");
        }
    } else {
        strError = GetLuaError(lua_state, luaStatus, "luaL_loadbuffer failed");
    }

    if (luaStatus != LUA_OK) {
        LogPrint("vm", "%s\n", strError);
        ReportBurnState(lua_state, pVmRunEnv);
        return std::make_tuple(-1, strError);
    }

    // 6. account balance check setting: default is closed if not such setting in the script
    pVmRunEnv->SetCheckAccount(false);
    int32_t res = lua_getglobal(lua_state, "gCheckAccount");
    LogPrint("vm", "lua_getglobal:%d\n", res);
    if (LUA_TBOOLEAN == res) {
        if (lua_isboolean(lua_state, -1)) {
            bool bCheck = lua_toboolean(lua_state, -1);
            LogPrint("vm", "lua_toboolean:%d\n", bCheck);
            pVmRunEnv->SetCheckAccount(bCheck);
        }
    }

    lua_pop(lua_state, 1);

    uint64_t burnedFuel = lua_GetBurnedFuel(lua_state);
    ReportBurnState(lua_state, pVmRunEnv);
    if (burnedFuel > fuelLimit) {
        return std::make_tuple(-1, string("CLuaVM::Run burned-out"));
    }

    return std::make_tuple(burnedFuel, string("CLuaVM::Run done"));
}
