// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2017-2019 The SXL Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CONFIG_ERRORCODE_H
#define CONFIG_ERRORCODE_H

#include <string>

/** "reject" message codes **/
static const uint8_t REJECT_MALFORMED               = 0x01;

static const uint8_t REJECT_INVALID                 = 0x10;
static const uint8_t REJECT_OBSOLETE                = 0x11;
static const uint8_t REJECT_DUPLICATE               = 0x12;

static const uint8_t REJECT_NONSTANDARD             = 0x20;
static const uint8_t REJECT_DUST                    = 0x21;
static const uint8_t REJECT_INSUFFICIENTFEE         = 0x22;

static const uint8_t READ_ACCOUNT_FAIL              = 0X30;
static const uint8_t WRITE_ACCOUNT_FAIL             = 0X31;
static const uint8_t UPDATE_ACCOUNT_FAIL            = 0X32;

static const uint8_t READ_SCRIPT_FAIL               = 0X40;
static const uint8_t WRITE_SCRIPT_FAIL              = 0X41;

static const uint8_t WRITE_CANDIDATE_VOTES_FAIL     = 0X50;
static const uint8_t OPERATE_CANDIDATE_VOTES_FAIL   = 0X51;

static const uint8_t UCOIN_STAKE_FAIL               = 0X60;

static const uint8_t WRITE_RECORD_FAIL              = 0X70;

#endif //CONFIG_ERRORCODE_H