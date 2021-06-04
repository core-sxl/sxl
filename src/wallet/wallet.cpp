// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"

#include "commons/base58.h"

#include <openssl/rand.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include "commons/random.h"
#include "config/configuration.h"
#include "commons/json/json_spirit_value.h"
#include "commons/json/json_spirit_writer_template.h"
#include "net.h"
#include "persistence/accountdb.h"
#include "persistence/contractdb.h"

using namespace json_spirit;
using namespace boost::assign;
using namespace std;
using namespace boost;

string CWallet::defaultFileName("");

bool CWallet::Unlock(const SecureString &strWalletPassphrase) {
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        for (const auto &pMasterKey : mapMasterKeys) {
            if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt,
                                              pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue;  // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }

    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString &strOldWalletPassphrase,
                                     const SecureString &strNewWalletPassphrase) {
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        for (auto &pMasterKey : mapMasterKeys) {
            if (!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt,
                                              pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey)) {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                                             pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                    pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                                             pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                    (pMasterKey.second.nDeriveIterations +
                     pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) /
                    2;

                if (pMasterKey.second.nDeriveIterations < 25000) pMasterKey.second.nDeriveIterations = 25000;

                LogPrint("INFO", "Wallet passphrase changed to an nDeriveIterations of %i\n",
                         pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                                                  pMasterKey.second.nDeriveIterations,
                                                  pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

//// Call after CreateTransaction unless you want to abort
std::tuple<bool, string> CWallet::CommitTx(CBaseTx *pTx) {
    LOCK2(cs_main, cs_wallet);
    LogPrint("INFO", "CommitTx() : %s\n", pTx->ToString(*pCdMan->pAccountCache));

    {
        CValidationState state;
        if (!::AcceptToMemoryPool(mempool, state, pTx, false)) {
            // This must not fail. The transaction has already been signed and recorded.
            LogPrint("INFO", "CommitTx() : invalid transaction %s\n", state.GetRejectReason());
            return std::make_tuple(false, state.GetRejectReason());
        }
    }

    uint256 txid = pTx->GetHash();
    ::RelayTransaction(pTx, txid);

    return std::make_tuple(true, txid.GetHex());
}

DBErrors CWallet::LoadWallet(bool fFirstRunRet) {
    // fFirstRunRet = false;
    return CWalletDB(strWalletFile, "cr+").LoadWallet(this);
}

int64_t CWallet::GetFreeBcoins(bool isConfirmed) const {
    int64_t ret = 0;
    {
        LOCK2(cs_main, cs_wallet);
        set<CKeyID> setKeyId;
        GetKeys(setKeyId);
        for (auto &keyId : setKeyId) {
            if (!isConfirmed)
                ret += mempool.cw->accountCache.GetAccountFreeAmount(keyId, SYMB::SXL);
            else
                ret += pCdMan->pAccountCache->GetAccountFreeAmount(keyId, SYMB::SXL);
        }
    }
    return ret;
}

bool CWallet::EncryptWallet(const SecureString &strWalletPassphrase) {
    if (IsEncrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;
    RandAddSeedPerfmon();

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                 kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations =
        (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) /
        2;

    if (kMasterKey.nDeriveIterations < 25000) kMasterKey.nDeriveIterations = 25000;

    LogPrint("INFO", "Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations,
                                      kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked) {
            assert(!pWalletDbEncryption);
            pWalletDbEncryption = new CWalletDB(strWalletFile);
            if (!pWalletDbEncryption->TxnBegin()) {
                delete pWalletDbEncryption;
                pWalletDbEncryption = nullptr;
                return false;
            }
            pWalletDbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey)) {
            if (fFileBacked) {
                pWalletDbEncryption->TxnAbort();
                delete pWalletDbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload their unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pWalletDbEncryption);

        if (fFileBacked) {
            if (!pWalletDbEncryption->TxnCommit()) {
                delete pWalletDbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload their unencrypted wallet.
                assert(false);
            }

            delete pWalletDbEncryption;
            pWalletDbEncryption = nullptr;
        }

        Lock();
        Unlock(strWalletPassphrase);
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);
    }

    return true;
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB *pWalletDbIn) {
    LOCK(cs_wallet);  // nWalletVersion
    if (nWalletVersion >= nVersion) return true;

    nWalletVersion = nVersion;
    if (fFileBacked) {
        CWalletDB *pWalletDb = pWalletDbIn ? pWalletDbIn : new CWalletDB(strWalletFile);
        pWalletDb->WriteMinVersion(nWalletVersion);
        if (!pWalletDbIn) delete pWalletDb;
    }

    return true;
}

bool CWallet::StartUp(string &strWalletFile) {
    auto InitError = [](const string &str) {
        LogPrint("ERROR", "%s\n", str);
        return true;
    };

    auto InitWarning = [](const string &str) {
        LogPrint("ERROR", "%s\n", str);
        return true;
    };

    defaultFileName   = SysCfg().GetArg("-wallet", "wallet.dat");
    string strDataDir = GetDataDir().string();

    // Wallet file must be a plain filename without a directory
    if (defaultFileName != boost::filesystem::basename(defaultFileName) + boost::filesystem::extension(defaultFileName))
        return InitError(strprintf(("Wallet %s resides outside data directory %s"), defaultFileName, strDataDir));

    if (strWalletFile == "") {
        strWalletFile = defaultFileName;
    }
    LogPrint("INFO", "Using wallet %s\n", strWalletFile);

    if (!bitdb.Open(GetDataDir())) {
        // try moving the database env out of the way
        boost::filesystem::path pathDatabase    = GetDataDir() / "database";
        boost::filesystem::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime());
        try {
            boost::filesystem::rename(pathDatabase, pathDatabaseBak);
            LogPrint("INFO", "Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        } catch (boost::filesystem::filesystem_error &error) {
            // failure is ok (well, not really, but it's not worse than what we started with)
        }

        // try again
        if (!bitdb.Open(GetDataDir())) {
            // if it still fails, it probably means we can't even create the database env
            string msg = strprintf(_("Error initializing wallet database environment %s!"), strDataDir);
            return InitError(msg);
        }
    }

    if (SysCfg().GetBoolArg("-salvagewallet", false)) {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, strWalletFile, true))
            return false;
    }

    if (filesystem::exists(GetDataDir() / strWalletFile)) {
        CDBEnv::VerifyResult r = bitdb.Verify(strWalletFile, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK) {
            string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."),
                                   strDataDir);
            InitWarning(msg);
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(_("wallet.dat corrupt, salvage failed"));
    }

    return true;
}

CWallet *CWallet::GetInstance() {
    string strWalletFile("");
    if (StartUp(strWalletFile)) {
        return new CWallet(strWalletFile);
    }

    return nullptr;
}

uint256 CWallet::GetCheckSum() const {
    CHashWriter ss(SER_GETHASH, CLIENT_VERSION);
    ss << nWalletVersion << mapMasterKeys;
    return ss.GetHash();
}

bool CWallet::CleanAll() {
    if (!IsEncrypted()) {
        for_each(mapKeys.begin(), mapKeys.end(), [&](std::map<CKeyID, CKeyCombi>::reference item) {
            CWalletDB(strWalletFile).EraseKeyStoreValue(item.first);
        });
        mapKeys.clear();
    } else {
        return ERRORMSG("wallet is encrypted hence clear data forbidden!");
    }
    return true;
}

bool CWallet::Sign(const CKeyID &keyId, const uint256 &hash, vector<uint8_t> &signature, bool isMiner) const {
    CKey key;
    if (GetKey(keyId, key, isMiner)) {
        return (key.Sign(hash, signature));
    }

    return false;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<uint8_t> &vchCryptedSecret) {
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;

    if (!fFileBacked)
        return true;

    {
        LOCK(cs_wallet);
        if (pWalletDbEncryption)
            return pWalletDbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
    return false;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<uint8_t> &vchCryptedSecret) {
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddKey(const CKey &key, const CKey &minerKey) {
    if ((!key.IsValid()) || (!minerKey.IsValid()))
        return false;

    CKeyCombi keyCombi(key, minerKey, nWalletVersion);
    return AddKey(key.GetPubKey().GetKeyId(), keyCombi);
}

bool CWallet::AddKey(const CKeyID &KeyId, const CKeyCombi &keyCombi) {
    if (!fFileBacked)
        return true;

    if (keyCombi.HaveMainKey()) {
        if (KeyId != keyCombi.GetCKeyID())
            return false;
    }

    if (!CWalletDB(strWalletFile).WriteKeyStoreValue(KeyId, keyCombi, nWalletVersion))
        return false;

    return CCryptoKeyStore::AddKeyCombi(KeyId, keyCombi);
}

bool CWallet::AddKey(const CKey &key) {
    if (!key.IsValid())
        return false;

    CKeyCombi keyCombi(key, nWalletVersion);
    return AddKey(key.GetPubKey().GetKeyId(), keyCombi);
}

bool CWallet::RemoveKey(const CKey &key) {
    CKeyID keyId = key.GetPubKey().GetKeyId();
    mapKeys.erase(keyId);
    if (!IsEncrypted()) {
        CWalletDB(strWalletFile).EraseKeyStoreValue(keyId);
    } else {
        return ERRORMSG("wallet is encrypted hence remove key forbidden!");
    }

    return true;
}

bool CWallet::IsReadyForCoolMiner(const CAccountDBCache &accountView) const {
    CRegID regId;
    for (auto const &item : mapKeys) {
        if (item.second.HaveMinerKey() && accountView.GetRegId(item.first, regId)) {
            return true;
        }
    }

    return false;
}

bool CWallet::ClearAllMainKeysForCoolMiner() {
    for (auto &item : mapKeys) {
        if (item.second.CleanMainKey()) {
            CWalletDB(strWalletFile).WriteKeyStoreValue(item.first, item.second, nWalletVersion);
        }
    }
    return true;
}

CWallet::CWallet(string strWalletFileIn) {
    SetNull();
    strWalletFile = strWalletFileIn;
    fFileBacked   = true;
}

void CWallet::SetNull() {
    nWalletVersion      = 0;
    fFileBacked         = false;
    nMasterKeyMaxID     = 0;
    pWalletDbEncryption = nullptr;
}

bool CWallet::LoadMinVersion(int32_t nVersion) {
    AssertLockHeld(cs_wallet);
    nWalletVersion = nVersion;

    return true;
}

int32_t CWallet::GetVersion() {
    LOCK(cs_wallet);
    return nWalletVersion;
}
