/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "gmock/gmock.h"
#include "gtest/gtest.h"

/* Calypsonet Terminal Calypso */
#include "CardTransactionManager.h"
#include "UnauthorizedKeyException.h"

/* Calypsonet Terminal Card */
#include "CardSelectionResponseApi.h"

/* Keyple Card Calypso */
#include "ApduRequestAdapter.h"
#include "CalypsoCardAdapter.h"
#include "CalypsoExtensionService.h"
#include "CalypsoSamAdapter.h"
#include "CardRequestAdapter.h"
#include "CardResponseAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"
#include "IllegalArgumentException.h"

/* Keyple Core Service */
#include "CardSelectionResponseAdapter.h"

/* Mock */
#include "ApduResponseAdapterMock.h"
#include "CardResponseAdapterMock.h"
#include "CardSelectionResponseApiMock.h"
#include "ReaderMock.h"
#include "SearchCommandDataMock.h"

using namespace testing;

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace keyple::card::calypso;
using namespace keyple::core::service;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;


class CardRequestMatcher : public CardRequestSpi /*: public ArgumentMatcher<CardRequestSpi> */{
public:
    /**
     *
     */
    CardRequestMatcher(const std::shared_ptr<CardRequestSpi> cardRequest)
    {
        mLeftApduRequests = cardRequest->getApduRequests();
    }

    //@Override
    bool matches(const std::shared_ptr<CardRequestSpi> right)
    {
        if (right == nullptr) {
            return false;
        }

        std::vector<std::shared_ptr<ApduRequestSpi>> rightApduRequests =
            right->getApduRequests();
        if (mLeftApduRequests.size() != rightApduRequests.size()) {
            return false;
        }

        auto itLeft = mLeftApduRequests.begin();
        auto itRight = rightApduRequests.begin();
        while (itLeft != mLeftApduRequests.end() && itRight != rightApduRequests.end()) {
            const std::vector<uint8_t> leftApdu = (*itLeft)->getApdu();
            const std::vector<uint8_t> rightApdu = (*itRight)->getApdu();
            if (!Arrays::equals(leftApdu, rightApdu)) {
                return false;
            }
        }

        return true;
    }

private:
    /**
     *
     */
    std::vector<std::shared_ptr<ApduRequestSpi>> mLeftApduRequests;
};

static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3 =
"6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C20051410019000";
static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN =
    "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C21051410019000";
static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE =
    "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C22051410019000";
static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2 =
    "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C02051410019000";
static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE =
    "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C12051410019000";
static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED =
    "6F238409315449432E49434131A516BF0C13C708000000001122334453070A3C20051410016283";
static const std::string SELECT_APPLICATION_RESPONSE_LIGHT =
    "6F238409315449432E49434134A516BF0C13C70800000000112233445307064390312B01009000";
static const std::string SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";
static const std::string HSM_C1_POWER_ON_DATA = "3B3F9600805A4880C108501711223344829000";
static const std::string FCI_REV10 =
    "6F228408315449432E494341A516BF0C13C708   0000000011223344 5307060A01032003119000";
static const std::string FCI_REV24 =
    "6F2A8410A0000004040125090101000000000000A516BF0C13C708 0000000011223344 53070A2E11420001019000";
static const std::string FCI_REV31 =
    "6F238409315449432E49434131A516BF0C13C708 0000000011223344 53070A3C23121410019000";
static const std::string FCI_STORED_VALUE_REV31 =
    "6F238409315449432E49434131A516BF0C13C708 0000000011223344 53070A3C23201410019000";
static const std::string FCI_REV31_INVALIDATED =
    "6F238409315449432E49434131A516BF0C13C708 0000000011223344 53070A3C23121410016283";

static const std::string ATR1 = "3B3F9600805A0080C120000012345678829000";

static const std::string PIN_OK = "1234";
static const std::string NEW_PIN = "4567";
static const std::string CIPHER_PIN_VERIFICATION_OK = "1122334455667788";
static const std::string CIPHER_PIN_UPDATE_OK = "88776655443322111122334455667788";
static const std::string PIN_5_DIGITS = "12345";
static const uint8_t PIN_CIPHERING_KEY_KIF = 0x11;
static const uint8_t PIN_CIPHERING_KEY_KVC = 0x22;

static const uint8_t FILE7 = 0x07;
static const uint8_t FILE8 = 0x08;
static const uint8_t FILE9 = 0x09;
static const uint8_t FILE10 = 0x10;
static const uint8_t FILE11 = 0x11;

static const std::string SW1SW2_OK = "9000";
static const std::string SW1SW2_KO = "6700";
static const std::string SW1SW2_6200 = "6200";
static const std::string SW1SW2_INCORRECT_SIGNATURE = "6988";
static const std::string SAM_CHALLENGE = "C1C2C3C4";
static const std::string CARD_CHALLENGE = "C1C2C3C4C5C6C7C8";
static const std::string CARD_DIVERSIFIER = "0000000011223344";
static const std::string SAM_SIGNATURE = "12345678";
static const std::string CARD_SIGNATURE = "9ABCDEF0";

static const std::string FILE7_REC1_29B =
    "7111111111111111111111111111111111111111111111111111111111";
static const std::string FILE7_REC2_29B =
    "7222222222222222222222222222222222222222222222222222222222";
static const std::string FILE7_REC3_29B =
    "7333333333333333333333333333333333333333333333333333333333";
static const std::string FILE7_REC4_29B =
    "7444444444444444444444444444444444444444444444444444444444";
static const std::string FILE7_REC1_4B = "00112233";
static const std::string FILE8_REC1_29B =
    "8111111111111111111111111111111111111111111111111111111111";
static const std::string FILE8_REC1_5B = "8122334455";
static const std::string FILE8_REC1_4B = "84332211";
static const std::string FILE9_REC1_4B = "8899AABB";

static const std::string FILE10_REC1_COUNTER =
    "00112200000000000000000000000000000000000000000000000000000000000000";
static const std::string FILE11_REC1_COUNTER =
    "00221100000000000000000000000000000000000000000000000000000000000000";

static const std::string FILE7_REC1_COUNTER1 = "A55AA5";
static const std::string FILE7_REC1_COUNTER2 = "5AA55A";

static const std::string REC_COUNTER_1000 = "0003E8";
static const std::string REC_COUNTER_2000 = "0007D0";

static const std::vector<uint8_t> FILE7_REC1_29B_BYTES = HexUtil::toByteArray(FILE7_REC1_29B);
static const std::vector<uint8_t> FILE7_REC2_29B_BYTES = HexUtil::toByteArray(FILE7_REC2_29B);
static const std::vector<uint8_t> FILE7_REC3_29B_BYTES = HexUtil::toByteArray(FILE7_REC3_29B);
static const std::vector<uint8_t> FILE7_REC4_29B_BYTES = HexUtil::toByteArray(FILE7_REC4_29B);
static const std::vector<uint8_t> FILE8_REC1_29B_BYTES = HexUtil::toByteArray(FILE8_REC1_29B);
static const std::vector<uint8_t> FILE8_REC1_5B_BYTES = HexUtil::toByteArray(FILE8_REC1_5B);
static const std::vector<uint8_t> FILE8_REC1_4B_BYTES = HexUtil::toByteArray(FILE8_REC1_4B);

//static const uint16_t LID_3F00 = (short) 0x3F00;
//static const uint16_t LID_0002 = (short) 0x0002;
//static const uint16_t LID_0003 = (short) 0x0003;
static const std::string LID_3F00_STR = "3F00";
static const std::string LID_0002_STR = "0002";
static const std::string LID_0003_STR = "0003";
static const std::string ACCESS_CONDITIONS_1234 = "10100000";
static const std::string KEY_INDEXES_1234 = "01030101";
static const std::string ACCESS_CONDITIONS_0002 = "1F000000";
static const std::string KEY_INDEXES_0002 = "01010101";
static const std::string ACCESS_CONDITIONS_0003 = "01100000";
static const std::string KEY_INDEXES_0003 = "01020101";

static const std::string CIPHERED_KEY =
    "000102030405060708090A0B0C0D0E0FF0E0D0C0B0A090807060504030201000";

static const std::string SW1SW2_OK_RSP = SW1SW2_OK;
static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD =
    "008A0B3904" + SAM_CHALLENGE + "00";
static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP =
    "030490980030791D" + FILE7_REC1_29B + SW1SW2_OK;
static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_NOT_RATIFIED_RSP =
    "030490980130791D" + FILE7_REC1_29B + SW1SW2_OK;
static const std::string CARD_OPEN_SECURE_SESSION_CMD = "008A030104" + SAM_CHALLENGE + "00";
static const std::string CARD_OPEN_SECURE_SESSION_RSP = "0304909800307900" + SW1SW2_OK;
static const std::string CARD_OPEN_SECURE_SESSION_KVC_78_CMD = "0304909800307800" + SW1SW2_OK;
static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_2_4_CMD = "948A8B3804C1C2C3C400";
static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_2_4_RSP =
    "79030D307124B928480805CBABAE30001240800000000000000000000000000000009000";
static const std::string CARD_CLOSE_SECURE_SESSION_CMD = "008E800004" + SAM_SIGNATURE + "00";
static const std::string CARD_CLOSE_SECURE_SESSION_NOT_RATIFIED_CMD =
    "008E000004" + SAM_SIGNATURE + "00";
static const std::string CARD_CLOSE_SECURE_SESSION_RSP = CARD_SIGNATURE + SW1SW2_OK;
static const std::string CARD_CLOSE_SECURE_SESSION_FAILED_RSP = "6988";
static const std::string CARD_ABORT_SECURE_SESSION_CMD = "008E000000";
static const std::string CARD_RATIFICATION_CMD = "00B2000000";
static const std::string CARD_RATIFICATION_RSP = "6B00";

static const std::string CARD_READ_REC_SFI7_REC1_CMD = "00B2013C00";
static const std::string CARD_READ_REC_SFI7_REC1_L29_CMD = "00B2013C1D";
static const std::string CARD_READ_REC_SFI7_REC1_RSP = FILE7_REC1_29B + SW1SW2_OK;
static const std::string CARD_READ_REC_SFI7_REC1_6B_COUNTER_CMD = "00B2013C06";
static const std::string CARD_READ_REC_SFI7_REC1_6B_COUNTER_RSP =
    FILE7_REC1_COUNTER1 + FILE7_REC1_COUNTER2 + SW1SW2_OK;
static const std::string CARD_READ_REC_SFI8_REC1_CMD = "00B2014400";
static const std::string CARD_READ_REC_SFI8_REC1_RSP = FILE8_REC1_29B + SW1SW2_OK;
static const std::string CARD_READ_REC_SFI7_REC3_4_CMD = "00B2033D3E";
static const std::string CARD_READ_REC_SFI7_REC3_4_RSP =
    "031D" + FILE7_REC3_29B + "041D" + FILE7_REC4_29B + SW1SW2_OK;
static const std::string CARD_READ_REC_SFI10_REC1_CMD = "00B2018400";
static const std::string CARD_READ_REC_SFI10_REC1_RSP = FILE10_REC1_COUNTER + SW1SW2_OK;
static const std::string CARD_READ_REC_SFI11_REC1_CMD = "00B2018C00";
static const std::string CARD_READ_REC_SFI11_REC1_RSP = FILE11_REC1_COUNTER + SW1SW2_OK;
static const std::string CARD_READ_RECORDS_FROM1_TO2_CMD = "00B2010D06";
static const std::string CARD_READ_RECORDS_FROM1_TO2_RSP = "010111020122" + SW1SW2_OK;
static const std::string CARD_READ_RECORDS_FROM3_TO4_CMD = "00B2030D06";
static const std::string CARD_READ_RECORDS_FROM3_TO4_RSP = "030133040144" + SW1SW2_OK;
static const std::string CARD_READ_RECORDS_FROM5_TO5_CMD = "00B2050C01";
static const std::string CARD_READ_RECORDS_FROM5_TO5_RSP = "55" + SW1SW2_OK;
static const std::string CARD_UPDATE_REC_SFI7_REC1_4B_CMD = "00DC013C0400112233";
static const std::string CARD_UPDATE_REC_SFI8_REC1_29B_CMD = "00DC01441D" + FILE8_REC1_29B;
static const std::string CARD_UPDATE_REC_SFI8_REC1_5B_CMD = "00DC014405" + FILE8_REC1_5B;
static const std::string CARD_UPDATE_REC_SFI8_REC1_4B_CMD = "00DC014404" + FILE8_REC1_4B;
static const std::string CARD_UPDATE_REC_SFI8_REC1_29B_2_4_CMD = "94DC01441D" + FILE8_REC1_29B;
static const std::string CARD_WRITE_REC_SFI8_REC1_4B_CMD = "00D2014404" + FILE8_REC1_4B;
static const std::string CARD_APPEND_REC_SFI9_REC1_4B_CMD = "00E2004804" + FILE9_REC1_4B;
static const std::string CARD_DECREASE_SFI10_CNT1_100U_CMD = "003001080300006400";
static const std::string CARD_DECREASE_SFI10_CNT1_4286U_RSP = "0010BE9000";
static const std::string CARD_INCREASE_SFI11_CNT1_100U_CMD = "003201080300006400";
static const std::string CARD_INCREASE_SFI11_CNT1_8821U_RSP = "0022759000";
static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD =
    "003A00080C01000001020000020300000300";
static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP =
    "0100001102000022030000339000";
static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD =
    "003A000808010000010200000200";
static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP = "01000011020000229000";
static const std::string CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD = "003A0008040300000300";
static const std::string CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP = "030000339000";
static const std::string CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD =
    "003800080C01000011020000220800008800";
static const std::string CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP =
    "0100011102000222080008889000";
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_CMD =
        "00A2010F070000021234FFFF00";
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_RSP = "020406" + SW1SW2_OK;
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_CMD =
        "00A2010F07000002123456FF00";
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_RSP = "020406" + SW1SW2_OK;
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_CMD =
        "00A2010F070000021234567700";
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_RSP = "020406" + SW1SW2_OK;
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD =
        "00A20227078103021234FFFF00";
static const std::string
    CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP =
        "020406112233123456" + SW1SW2_OK;
static const std::string CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_CMD =
    "00B3010D045402030100";
static const std::string CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_RSP =
    "1122" + SW1SW2_6200;
static const std::string CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_CMD =
    "00B3030D045402030100";
static const std::string CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_RSP =
    "3344" + SW1SW2_6200;
static const std::string CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_CMD =
    "00B3050D045402030100";
static const std::string CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_RSP = "55" + SW1SW2_OK;
static const std::string CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD = "00B0810001";
static const std::string CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP = "11" + SW1SW2_OK;
static const std::string CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD = "00B0010001";
static const std::string CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP = "66" + SW1SW2_OK;
static const std::string CARD_READ_BINARY_SFI1_OFFSET0_2B_CMD = "00B0810002";
static const std::string CARD_READ_BINARY_SFI1_OFFSET0_2B_RSP = "1122" + SW1SW2_OK;
static const std::string CARD_READ_BINARY_SFI1_OFFSET2_2B_CMD = "00B0810202";
static const std::string CARD_READ_BINARY_SFI1_OFFSET2_2B_RSP = "3344" + SW1SW2_OK;
static const std::string CARD_READ_BINARY_SFI1_OFFSET4_1B_CMD = "00B0810401";
static const std::string CARD_READ_BINARY_SFI1_OFFSET4_1B_RSP = "55" + SW1SW2_OK;
static const std::string CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD = "00D68100021122";
static const std::string CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD = "00D68102023344";
static const std::string CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD = "00D681040155";
static const std::string CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD = "00D601000166";
static const std::string CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD = "00D08100021122";
static const std::string CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD = "00D08102023344";
static const std::string CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD = "00D081040155";
static const std::string CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD = "00D001000166";

static const std::string CARD_SELECT_FILE_CURRENT_CMD = "00A4090002000000";
static const std::string CARD_SELECT_FILE_FIRST_CMD = "00A4020002000000";
static const std::string CARD_SELECT_FILE_NEXT_CMD = "00A4020202000000";
static const std::string CARD_SELECT_FILE_1234_CMD = "00A4090002123400";
static const std::string CARD_SELECT_FILE_1234_RSP =
    "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";
static const std::string CARD_SELECT_FILE_1234_CMD_PRIME_REV2 = "94A4020002123400";
static const std::string CARD_SELECT_FILE_1234_RSP_PRIME_REV2 =
    "85170001000000" + ACCESS_CONDITIONS_1234 + KEY_INDEXES_1234 + "00777879616770003F009000";

static const std::string CARD_GET_DATA_FCI_CMD = "00CA006F00";
static const std::string CARD_GET_DATA_FCP_CMD = "00CA006200";
static const std::string CARD_GET_DATA_EF_LIST_CMD = "00CA00C000";
static const std::string CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD = "00CA018500";
static const std::string CARD_GET_DATA_FCI_RSP = SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3;
static const std::string CARD_GET_DATA_FCP_RSP = CARD_SELECT_FILE_1234_RSP;
static const std::string CARD_GET_DATA_EF_LIST_RSP =
    "C028C106200107021D01C10620FF09011D04C106F1231004F3F4C106F1241108F3F4C106F1251F09F3F49000";
static const std::string CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP =
    "001122334455667788999000";

static const std::string CARD_VERIFY_PIN_PLAIN_OK_CMD =
    "0020000004" + HexUtil::toHex(std::vector<uint8_t>(PIN_OK.begin(), PIN_OK.end()));
static const std::string CARD_VERIFY_PIN_ENCRYPTED_OK_CMD =
    "0020000008" + CIPHER_PIN_VERIFICATION_OK;
static const std::string CARD_CHECK_PIN_CMD = "0020000000";
static const std::string CARD_CHANGE_PIN_CMD = "00D800FF10" + CIPHER_PIN_UPDATE_OK;
static const std::string CARD_CHANGE_PIN_PLAIN_CMD =
    "00D800FF04" + HexUtil::toHex(std::vector<uint8_t>(NEW_PIN.begin(), NEW_PIN.end()));
static const std::string CARD_VERIFY_PIN_OK_RSP = SW1SW2_OK;
static const std::string CARD_VERIFY_PIN_KO_RSP = "63C2";
static const std::string CARD_CHANGE_PIN_RSP = SW1SW2_OK;
static const std::string CARD_CHANGE_PIN_PLAIN_RSP = SW1SW2_OK;

//static const int SV_BALANCE = 0x123456;
static const std::string SV_BALANCE_STR = "123456";
static const std::string CARD_SV_GET_DEBIT_CMD = "007C000900";
static const std::string CARD_SV_GET_DEBIT_RSP =
    "790073A54BC97DFA" + SV_BALANCE_STR + "FFFE0000000079123456780000DD0000160072" + SW1SW2_OK;
static const std::string CARD_SV_GET_RELOAD_CMD = "007C000700";
static const std::string CARD_PRIME_REV2_SV_GET_RELOAD_CMD = "FA7C000700";
static const std::string CARD_SV_GET_RELOAD_RSP =
    "79007221D35F0E36"
        + SV_BALANCE_STR
        + "000000790000001A0000020000123456780000DB0070"
        + SW1SW2_OK;
static const std::string CARD_SV_RELOAD_CMD =
    "00B89591171600000079000000020000123456780000DE2C8CB3D280";
static const std::string CARD_SV_RELOAD_RSP = "A54BC9" + SW1SW2_OK;
static const std::string CARD_SV_DEBIT_CMD =
    "00BACD001434FFFE0000000079123456780000DF0C9437AABB";
static const std::string CARD_SV_DEBIT_RSP = "A54BC9" + SW1SW2_OK;
static const std::string CARD_SV_UNDEBIT_CMD =
    "00BCCD00143400020000000079123456780000DF0C9437AABB";
static const std::string CARD_SV_UNDEBIT_RSP = "A54BC9" + SW1SW2_OK;
static const std::string CARD_READ_SV_LOAD_LOG_FILE_CMD = "00B201A400";
static const std::string CARD_READ_SV_LOAD_LOG_FILE_RSP =
    "000000780000001A0000020000AABBCCDD0000DB007000000000000000" + SW1SW2_OK;
static const std::string CARD_READ_SV_DEBIT_LOG_FILE_CMD = "00B201AD5D";
static const std::string CARD_READ_SV_DEBIT_LOG_FILE_RSP =
    std::string("011DFFFE0000000079AABBCC010000DA000018006F00000000000000000000") +
    "021DFFFE0000000079AABBCC020000DA000018006F00000000000000000000" +
    "031DFFFE0000000079AABBCC030000DA000018006F00000000000000000000" +
    SW1SW2_OK;

static const std::string CARD_INVALIDATE_CMD = "0004000000";
static const std::string CARD_REHABILITATE_CMD = "0044000000";

static const std::string CARD_GET_CHALLENGE_CMD = "0084000008";
static const std::string CARD_GET_CHALLENGE_RSP = CARD_CHALLENGE + SW1SW2_OK;

static const std::string CARD_CHANGE_KEY_CMD = "00D8000120" + CIPHERED_KEY;

static const std::string SAM_SELECT_DIVERSIFIER_CMD = "8014000008" + CARD_DIVERSIFIER;
static const std::string SAM_GET_CHALLENGE_CMD = "8084000004";
static const std::string SAM_GET_CHALLENGE_RSP = SAM_CHALLENGE + SW1SW2_OK;
static const std::string SAM_DIGEST_INIT_OPEN_SECURE_SESSION_SFI7_REC1_CMD =
    "808A00FF273079030490980030791D" + FILE7_REC1_29B;
static const std::string SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD =
    "808A00FF0A30790304909800307900";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_CMD = "808C00000500B2013C00";
static const std::string SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC1_L29_CMD =
    std::string("808C8000") + "26" + "05" + "00B2013C1D" + "1F" + FILE7_REC1_29B + SW1SW2_OK;
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP_CMD =
    "808C00001F\" + FILE7_REC1_29B+ \"9000";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI8_REC1_RSP_CMD =
    "808C00001F" + FILE8_REC1_29B + "9000";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_L29_CMD = "808C00000500B2013C1D";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP =
    "808C00001F" + FILE7_REC1_29B + SW1SW2_OK;
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI8_REC1_CMD = "808C00000500B2014400";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI10_REC1_CMD = "808C00000500B2018C00";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI10_REC1_RSP_CMD =
    "808C000024001122000000000000000000000000000000000000000000000000000000000000009000";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI11_REC1_CMD = "808C00000500B2018400";
static const std::string SAM_DIGEST_UPDATE_READ_REC_SFI11_REC1_RSP_CMD =
    "808C000024002211000000000000000000000000000000000000000000000000000000000000009000";
static const std::string SAM_DIGEST_UPDATE_RSP_OK_CMD = "808C0000029000";
static const std::string SAM_DIGEST_UPDATE_UPDATE_REC_SFI8_REC1_29B_CMD =
    "808C00002200DC01441D" + FILE8_REC1_29B;
static const std::string SAM_DIGEST_UPDATE_UPDATE_REC_SFI8_REC1_5B_CMD =
    "808C00000A00DC0144058122334455";
static const std::string SAM_DIGEST_UPDATE_UPDATE_REC_SFI8_REC1_4B_CMD =
    "808C00000900DC014404" + FILE8_REC1_4B;
static const std::string SAM_DIGEST_UPDATE_UPDATE_REC_SFI7_REC1_4B_CMD =
    "808C00000900DC013C04" + FILE7_REC1_4B;
static const std::string SAM_DIGEST_UPDATE_DECREASE_SFI10_CMD = "808C0000080030018003000064";
static const std::string SAM_DIGEST_UPDATE_DECREASE_SFI10_RESP = "808C0000050010BE9000";
static const std::string SAM_DIGEST_UPDATE_INCREASE_SFI11_CMD = "808C0000080032018803000064";
static const std::string SAM_DIGEST_UPDATE_INCREASE_SFI11_RESP = "808C0000050022759000";
static const std::string SAM_DIGEST_UPDATE_WRITE_REC_SFI8_REC1_4B_CMD =
    "808C00000900D2014404" + FILE8_REC1_4B;
static const std::string SAM_DIGEST_UPDATE_APPEND_REC_SFI9_REC1_4B_CMD =
    "808C00000900E2004804" + FILE9_REC1_4B;
static const std::string SAM_DIGEST_CLOSE_CMD = "808E000004";
static const std::string SAM_DIGEST_CLOSE_RSP = SAM_SIGNATURE + SW1SW2_OK;
static const std::string SAM_DIGEST_AUTHENTICATE_CMD = "8082000004" + CARD_SIGNATURE;
static const std::string SAM_DIGEST_AUTHENTICATE_FAILED = "6988";

static const std::string SAM_CARD_CIPHER_PIN_VERIFICATION_CMD =
    "801280FF060000" + HexUtil::toHex(std::vector<uint8_t>(PIN_OK.begin(), PIN_OK.end()));
static const std::string SAM_CARD_CIPHER_PIN_VERIFICATION_RSP =
    CIPHER_PIN_VERIFICATION_OK + SW1SW2_OK;
static const std::string SAM_CARD_CIPHER_PIN_UPDATE_CMD =
    "801240FF0A112200000000" +
    HexUtil::toHex(std::vector<uint8_t>(NEW_PIN.begin(), NEW_PIN.end()));
static const std::string SAM_CARD_CIPHER_PIN_UPDATE_RSP = CIPHER_PIN_UPDATE_OK + SW1SW2_OK;
static const std::string SAM_GIVE_RANDOM_CMD = "8086000008" + CARD_CHALLENGE;
static const std::string SAM_GIVE_RANDOM_RSP = SW1SW2_OK;
static const std::string SAM_PREPARE_LOAD_CMD =
    "805601FF367C00070079007221D35F0E36"
        + SV_BALANCE_STR
        + "000000790000001A0000020000123456780000DB00709000B80000170000000079000000020000";
static const std::string SAM_PREPARE_LOAD_RSP = "9591160000DE2C8CB3D280" + SW1SW2_OK;
static const std::string SAM_PREPARE_DEBIT_CMD =
    "805401FF307C000900790073A54BC97DFA"
        + SV_BALANCE_STR
        + "FFFE0000000079123456780000DD00001600729000BA00001400FFFE0000000079";
static const std::string SAM_PREPARE_DEBIT_RSP = "CD00340000DF0C9437AABB" + SW1SW2_OK;
static const std::string SAM_PREPARE_UNDEBIT_CMD =
    "805C01FF307C000900790073A54BC97DFA"
        + SV_BALANCE_STR
        + "FFFE0000000079123456780000DD00001600729000BC0000140000020000000079";
static const std::string SAM_PREPARE_UNDEBIT_RSP = "CD00340000DF0C9437AABB" + SW1SW2_OK;
static const std::string SAM_SV_CHECK_CMD = "8058000003A54BC9";

static const std::string SAM_CARD_GENERATE_KEY_CMD = "8012FFFF050405020390";
static const std::string SAM_CARD_GENERATE_KEY_RSP = CIPHERED_KEY + SW1SW2_OK;

static std::shared_ptr<CardTransactionManager> cardTransactionManager;
static std::shared_ptr<CalypsoCardAdapter> calypsoCard;
static std::shared_ptr<ReaderMock> cardReader;
static std::shared_ptr<ReaderMock> samReader;
static std::shared_ptr<CalypsoSamAdapter> calypsoSam;
static std::shared_ptr<CardSecuritySetting> cardSecuritySetting;


static void initCalypsoCard(const std::string& selectApplicationResponse)
{
    calypsoCard = std::make_shared<CalypsoCardAdapter>();
    calypsoCard->initialize(
        std::make_shared<CardSelectionResponseAdapter>(
                std::make_shared<ApduResponseAdapter>(
                    HexUtil::toByteArray(selectApplicationResponse))));

    cardTransactionManager =
        CalypsoExtensionService::getInstance()
            ->createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);
}

static void setUp()
{
    cardReader = std::make_shared<ReaderMock>();

    samReader = std::make_shared<ReaderMock>();

    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData())
        .WillRepeatedly(ReturnRef(SAM_C1_POWER_ON_DATA));

    calypsoSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);

    cardSecuritySetting = CalypsoExtensionService::getInstance()->createCardSecuritySetting();
    cardSecuritySetting->setControlSamResource(samReader, calypsoSam);

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
}

static void tearDown()
{
    cardReader.reset();
    calypsoCard.reset();
    samReader.reset();
    calypsoSam.reset();
    cardTransactionManager.reset();
    cardSecuritySetting.reset();
}
static std::shared_ptr<CardRequestSpi> createCardRequest(
    const std::vector<std::string>& apduCommands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    for (const auto& apduCommand : apduCommands) {
        apduRequests.push_back(
            std::make_shared<ApduRequestAdapter>(HexUtil::toByteArray(apduCommand)));
    }

    return std::make_shared<CardRequestAdapter>(apduRequests, false);
  }

static std::shared_ptr<CardResponseApi> createCardResponse(
    const std::vector<std::string>& apduCommandResponses)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;

    for (const auto& apduResponse : apduCommandResponses) {
        apduResponses.push_back(
            std::make_shared<ApduResponseAdapterMock>(HexUtil::toByteArray(apduResponse)));
    }

    return std::make_shared<CardResponseAdapterMock>(apduResponses, true);
}

TEST(CardTransactionManagerAdapterTest, getCardReader_shouldReturnCardReader)
{
    setUp();

    ASSERT_EQ(cardTransactionManager->getCardReader(), cardReader);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, getCalypsoCard_shouldReturnCalypsoCard)
{
    setUp();

    ASSERT_EQ(cardTransactionManager->getCalypsoCard(), calypsoCard);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, getSecuritySetting_shouldReturnCardSecuritySetting)
{
    setUp();

    ASSERT_EQ(cardTransactionManager->getSecuritySetting(), cardSecuritySetting);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, getCardSecuritySetting_shouldReturnCardSecuritySetting)
{
    setUp();

    ASSERT_EQ(cardTransactionManager->getCardSecuritySetting(), cardSecuritySetting);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processOpening_whenNoCommandsArePrepared_shouldExchangeApduWithCardAndSam)
{
    setUp();

    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processOpening_whenSuccessful_shouldUpdateTransactionCounterAndRatificationStatus)
{
    setUp();

    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    ASSERT_TRUE(calypsoCard->isDfRatified());
    ASSERT_EQ(calypsoCard->getTransactionCounter(), 0x030490);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processOpening_whenOneReadRecordIsPrepared_shouldExchangeApduWithCardAndSam)
{
    setUp();

    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    tearDown();
}


TEST(CardTransactionManagerAdapterTest,
     processOpening_whenTwoReadRecordIsPrepared_shouldExchangeApduWithCardAndSam)
{
    setUp();

    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD, CARD_READ_REC_SFI8_REC1_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP, CARD_READ_REC_SFI8_REC1_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->prepareReadRecord(FILE8, 1);
    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processOpening_whenKeyNotAuthorized_shouldThrowUnauthorizedKeyException)
{
    setUp();

    /* Force the checking of the session key to fail */
    cardSecuritySetting = CalypsoExtensionService::getInstance()->createCardSecuritySetting();
    cardSecuritySetting->setControlSamResource(samReader, calypsoSam)
                        .addAuthorizedSessionKey(0x00, 0x00);

    cardTransactionManager =
        CalypsoExtensionService::getInstance()
        ->createCardTransaction(cardReader, calypsoCard, cardSecuritySetting);

    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillRepeatedly(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillRepeatedly(Return(cardCardResponse));

    EXPECT_THROW(cardTransactionManager->processOpening(WriteAccessLevel::DEBIT),
                 UnauthorizedKeyException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processCommands_whenOutOfSession_shouldExchangeApduWithCardOnly)
{
    setUp();

    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_READ_REC_SFI7_REC1_CMD,
                           CARD_READ_REC_SFI8_REC1_CMD,
                           CARD_READ_REC_SFI10_REC1_CMD});

    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_READ_REC_SFI7_REC1_RSP,
                            CARD_READ_REC_SFI8_REC1_RSP,
                            CARD_READ_REC_SFI10_REC1_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->prepareReadRecord(FILE8, 1);
    cardTransactionManager->prepareReadRecord(FILE10, 1);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processCardCommands_whenOutOfSession_shouldExchangeApduWithCardOnly)
{
    setUp();

    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_READ_REC_SFI7_REC1_CMD,
                           CARD_READ_REC_SFI8_REC1_CMD,
                           CARD_READ_REC_SFI10_REC1_CMD});

    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_READ_REC_SFI7_REC1_RSP,
                            CARD_READ_REC_SFI8_REC1_RSP,
                            CARD_READ_REC_SFI10_REC1_RSP});


    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->prepareReadRecord(FILE8, 1);
    cardTransactionManager->prepareReadRecord(FILE10, 1);
    cardTransactionManager->processCardCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processClosing_whenNoSessionIsOpen_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->processClosing(), IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processClosing_whenASessionIsOpenAndNotSamC1_shouldExchangeApduWithCardAndSamWithoutDigestUpdateMultiple)
{
    setUp();

    /* HSM */
    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData()).WillOnce(ReturnRef(HSM_C1_POWER_ON_DATA));

    calypsoSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);
    cardSecuritySetting = CalypsoExtensionService::getInstance()
                             ->createCardSecuritySetting();
    cardSecuritySetting->setControlSamResource(samReader, calypsoSam);
    cardTransactionManager = CalypsoExtensionService::getInstance()
                                 ->createCardTransaction(cardReader,
                                                         calypsoCard,
                                                         cardSecuritySetting);

    /* Open session */
    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);
    samCardRequest = createCardRequest({SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD,
                                        SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_L29_CMD,
                                        SAM_DIGEST_UPDATE_READ_REC_SFI7_REC1_RSP,
                                        SAM_DIGEST_CLOSE_CMD});

    std::shared_ptr<CardRequestSpi> cardCardRequestRead =
        createCardRequest({CARD_READ_REC_SFI7_REC1_L29_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequestClose =
        createCardRequest({CARD_CLOSE_SECURE_SESSION_CMD});

    samCardResponse = createCardResponse({SW1SW2_OK_RSP,
                                          SW1SW2_OK_RSP,
                                          SW1SW2_OK_RSP,
                                          SAM_DIGEST_CLOSE_RSP});

    std::shared_ptr<CardResponseApi> cardCardResponseRead =
        createCardResponse({CARD_READ_REC_SFI7_REC1_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponseClose =
        createCardResponse({CARD_CLOSE_SECURE_SESSION_RSP});

    std::shared_ptr<CardRequestSpi> samCardRequest2 =
        createCardRequest({SAM_DIGEST_AUTHENTICATE_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse2 =
        createCardResponse({SW1SW2_OK_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(samCardResponse))
        .WillOnce(Return(samCardResponse2));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _))
        .WillOnce(Return(cardCardResponseRead))
        .WillOnce(Return(cardCardResponseClose));

    cardTransactionManager->prepareReadRecords(FILE7, 1, 1, 29);
    cardTransactionManager->processClosing();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processClosing_whenASessionIsOpenAndSamC1_shouldExchangeApduWithCardAndSamWithDigestUpdateMultiple)
{
    setUp();

    /* Open session */
    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);
    samCardRequest = createCardRequest({SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD,
                                        SAM_DIGEST_UPDATE_MULTIPLE_READ_REC_SFI7_REC1_L29_CMD,
                                        SAM_DIGEST_CLOSE_CMD});

    std::shared_ptr<CardRequestSpi> cardCardRequestRead =
        createCardRequest({CARD_READ_REC_SFI7_REC1_L29_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequestClose =
        createCardRequest({CARD_CLOSE_SECURE_SESSION_CMD});

    samCardResponse = createCardResponse({SW1SW2_OK_RSP, SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP});

    std::shared_ptr<CardResponseApi> cardCardResponseRead =
        createCardResponse({CARD_READ_REC_SFI7_REC1_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponseClose =
        createCardResponse({CARD_CLOSE_SECURE_SESSION_RSP});

    std::shared_ptr<CardRequestSpi> samCardRequest2 =
        createCardRequest({SAM_DIGEST_AUTHENTICATE_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse2 =
        createCardResponse({SW1SW2_OK_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(samCardResponse))
        .WillOnce(Return(samCardResponse2));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _))
        .WillOnce(Return(cardCardResponseRead))
        .WillOnce(Return(cardCardResponseClose));

    cardTransactionManager->prepareReadRecords(FILE7, 1, 1, 29);
    cardTransactionManager->processClosing();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processClosing_whenCloseSessionFails_shouldThrowUCSE)
{
    setUp();

    /* Open session */
    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    samCardRequest = createCardRequest({SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD,
                                        SAM_DIGEST_CLOSE_CMD});
    cardCardRequest = createCardRequest({CARD_CLOSE_SECURE_SESSION_CMD});
    samCardResponse = createCardResponse({SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP});
    cardCardResponse = createCardResponse({SW1SW2_INCORRECT_SIGNATURE});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    EXPECT_THROW(cardTransactionManager->processClosing(), UnexpectedCommandStatusException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processClosing_whenCardAuthenticationFails_shouldThrowICSE)
{
    setUp();

    /* Open session */
    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    samCardRequest =
        createCardRequest({SAM_DIGEST_INIT_OPEN_SECURE_SESSION_CMD, SAM_DIGEST_CLOSE_CMD});
    cardCardRequest = createCardRequest({CARD_CLOSE_SECURE_SESSION_CMD});
    samCardResponse = createCardResponse({SW1SW2_OK_RSP, SAM_DIGEST_CLOSE_RSP});
    cardCardResponse = createCardResponse({CARD_CLOSE_SECURE_SESSION_RSP});

    const std::shared_ptr<CardRequestSpi> samCardRequest2 =
        createCardRequest({SAM_DIGEST_AUTHENTICATE_CMD});
    const std::shared_ptr<CardResponseApi> samCardResponse2 =
        createCardResponse({SW1SW2_INCORRECT_SIGNATURE});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(samCardResponse))
        .WillOnce(Return(samCardResponse2));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    EXPECT_THROW(cardTransactionManager->processClosing(), InvalidCardSignatureException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processCancel_whenNoSessionIsOpen_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->processCancel(), IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processCancel_whenASessionIsOpen_shouldSendCancelApduToCard)
{
    setUp();

    /* Open session */
    std::shared_ptr<CardRequestSpi> samCardRequest =
        createCardRequest({SAM_SELECT_DIVERSIFIER_CMD, SAM_GET_CHALLENGE_CMD});
    std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_OPEN_SECURE_SESSION_CMD});
    std::shared_ptr<CardResponseApi> samCardResponse =
        createCardResponse({SW1SW2_OK_RSP, SAM_GET_CHALLENGE_RSP});
    std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_OPEN_SECURE_SESSION_RSP});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(samCardResponse));
    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processOpening(WriteAccessLevel::DEBIT);

    cardCardRequest = createCardRequest({CARD_ABORT_SECURE_SESSION_CMD});
    cardCardResponse = createCardResponse({SW1SW2_OK});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processCancel();

    tearDown();
}

// C++: PIN comes as a vector reference, cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, processVerifyPin_whenPINIsNull_shouldThrowIAE)
// {
//     setUp();
//
//     EXPECT_CALL(cardTransactionManager.processVerifyPin(null), IllegalArgumentException;
//
//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, processVerifyPin_whenPINIsNot4Digits_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->processVerifyPin(
                     std::vector<uint8_t>(PIN_5_DIGITS.begin(), PIN_5_DIGITS.end())),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processVerifyPin_whenPINIsNotFirstCommand_shouldThrowISE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);
    cardTransactionManager->prepareReadRecord(FILE7, 1);

    EXPECT_THROW(cardTransactionManager->processVerifyPin(
                    std::vector<uint8_t>(PIN_OK.begin(), PIN_OK.end())),
                 IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processVerifyPin_whenPINNotAvailable_shouldThrowUOE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->processVerifyPin(
                    std::vector<uint8_t>(PIN_OK.begin(), PIN_OK.end())),
                 UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processVerifyPin_whenPINTransmittedInPlainText_shouldSendApduVerifyPIN)
{
    setUp();

    cardSecuritySetting = CalypsoExtensionService::getInstance()->createCardSecuritySetting();
    cardSecuritySetting->setControlSamResource(samReader, calypsoSam).enablePinPlainTransmission();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    const auto cardCardRequest = createCardRequest({CARD_VERIFY_PIN_PLAIN_OK_CMD});
    const auto cardCardResponse = createCardResponse({SW1SW2_OK});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->processVerifyPin(std::vector<uint8_t>(PIN_OK.begin(), PIN_OK.end()));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processChangePin_whenTransmissionIsPlain_shouldSendApdusToTheCardAndTheSAM)
{
    setUp();

    cardSecuritySetting = CalypsoExtensionService::getInstance()->createCardSecuritySetting();
    cardSecuritySetting->enablePinPlainTransmission().setControlSamResource(samReader, calypsoSam);

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    calypsoCard->setPinAttemptRemaining(3);

    const auto cardChangePinCardRequest = createCardRequest({CARD_CHANGE_PIN_PLAIN_CMD});
    const auto cardChangePinCardResponse = createCardResponse({CARD_CHANGE_PIN_PLAIN_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardChangePinCardResponse));

    cardTransactionManager->processChangePin(std::vector<uint8_t>(NEW_PIN.begin(), NEW_PIN.end()));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     processChangePin_whenTransmissionIsEncrypted_shouldSendApdusToTheCardAndTheSAM)
{
    setUp();

    cardSecuritySetting = CalypsoExtensionService::getInstance()->createCardSecuritySetting();
    cardSecuritySetting
        ->setPinModificationCipheringKey(PIN_CIPHERING_KEY_KIF, PIN_CIPHERING_KEY_KVC)
        .setControlSamResource(samReader, calypsoSam);

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    const auto cardGetChallengeCardRequest = createCardRequest({CARD_GET_CHALLENGE_CMD});
    const auto cardGetChallengeCardResponse = createCardResponse({CARD_GET_CHALLENGE_RSP});

    const auto samCardRequest = createCardRequest({SAM_SELECT_DIVERSIFIER_CMD,
                                                   SAM_GIVE_RANDOM_CMD,
                                                   SAM_CARD_CIPHER_PIN_UPDATE_CMD});
    const auto samCardResponse = createCardResponse({SW1SW2_OK,
                                                     SW1SW2_OK,
                                                     SAM_CARD_CIPHER_PIN_UPDATE_RSP});

    const auto cardChangePinCardRequest = createCardRequest({CARD_CHANGE_PIN_CMD});
    const auto cardChangePinCardResponse = createCardResponse({CARD_CHANGE_PIN_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _))
        .WillOnce(Return(cardGetChallengeCardResponse))
        .WillOnce(Return(cardChangePinCardResponse));

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(samCardResponse));

    cardTransactionManager->processChangePin(std::vector<uint8_t>(NEW_PIN.begin(), NEW_PIN.end()));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, processChangeKey_shouldSendApdusToTheCardAndTheSAM)
{
    setUp();

    cardSecuritySetting = CalypsoExtensionService::getInstance()->createCardSecuritySetting();
    cardSecuritySetting->setControlSamResource(samReader, calypsoSam).enablePinPlainTransmission();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    const auto cardGetChallengeCardRequest = createCardRequest({CARD_GET_CHALLENGE_CMD});
    const auto cardGetChallengeCardResponse = createCardResponse({CARD_GET_CHALLENGE_RSP});

    const auto samCardRequest = createCardRequest({SAM_SELECT_DIVERSIFIER_CMD,
                                                   SAM_GIVE_RANDOM_CMD,
                                                   SAM_CARD_GENERATE_KEY_CMD});
    const auto samCardResponse = createCardResponse({SW1SW2_OK,
                                                     SW1SW2_OK,SAM_CARD_GENERATE_KEY_RSP});

    const auto cardChangeKeyCardRequest = createCardRequest({CARD_CHANGE_KEY_CMD});
    const auto cardChangeKeyCardResponse = createCardResponse({SW1SW2_OK});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _))
        .WillOnce(Return(cardGetChallengeCardResponse))
        .WillOnce(Return(cardChangeKeyCardResponse));

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(samCardResponse));


    cardTransactionManager->processChangeKey(1,  2,  3,  4,  5);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFileDeprecated_whenLidIsLessThan2ByteLong_shouldThrowIAE)
{
    setUp();

    const std::vector<uint8_t> one(1);

    EXPECT_THROW(cardTransactionManager->prepareSelectFile(one), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFileDeprecated_whenLidIsMoreThan2ByteLong_shouldThrowIAE)
{
    setUp();

    const std::vector<uint8_t> three(3);

    EXPECT_THROW(cardTransactionManager->prepareSelectFile(three), IllegalArgumentException);
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFile_whenLidIs1234AndCardIsPrimeRevision3_shouldPrepareSelectFileApduWith1234)
{
    setUp();

    const uint16_t lid = 0x1234;
    const std::shared_ptr<CardRequestSpi> cardCardRequest =
        createCardRequest({CARD_SELECT_FILE_1234_CMD});
    const std::shared_ptr<CardResponseApi> cardCardResponse =
        createCardResponse({CARD_SELECT_FILE_1234_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSelectFile(lid);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFile_whenLidIs1234AndCardIsPrimeRevision2_shouldPrepareSelectFileApduWith1234)
{
    setUp();

    const uint16_t lid = 0x1234;

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    const auto cardCardRequest = createCardRequest({CARD_SELECT_FILE_1234_CMD_PRIME_REV2});
    const auto cardCardResponse = createCardResponse({CARD_SELECT_FILE_1234_RSP_PRIME_REV2});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSelectFile(lid);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFile_whenSelectFileControlIsFirstEF_shouldPrepareSelectFileApduWithP2_02_P1_00)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_SELECT_FILE_FIRST_CMD});
    const auto cardCardResponse = createCardResponse({CARD_SELECT_FILE_1234_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSelectFile(SelectFileControl::FIRST_EF);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFile_whenSelectFileControlIsNextEF_shouldPrepareSelectFileApduWithP2_02_P1_02)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_SELECT_FILE_NEXT_CMD});
    const auto cardCardResponse = createCardResponse({CARD_SELECT_FILE_1234_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSelectFile(SelectFileControl::NEXT_EF);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSelectFile_whenSelectFileControlIsCurrentEF_shouldPrepareSelectFileApduWithP2_09_P1_00)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_SELECT_FILE_CURRENT_CMD});
    const auto cardCardResponse = createCardResponse({CARD_SELECT_FILE_1234_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSelectFile(SelectFileControl::CURRENT_DF);
    cardTransactionManager->processCommands();

    tearDown();
}

// C++: data tag cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareGetData_whenGetDataTagIsNull_shouldThrowIAE)
// {
//     setUp();

//     EXPECT_THROW(cardTransactionManager->prepareGetData(null), IllegalArgumentException;

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,
     prepareGetData_whenGetDataTagIsFCP_shouldPrepareSelectFileApduWithTagFCP)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_GET_DATA_FCP_CMD});
    const auto cardCardResponse = createCardResponse({CARD_GET_DATA_FCP_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareGetData(GetDataTag::FCP_FOR_CURRENT_FILE);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareGetData_whenGetDataTagIsEF_LIST_shouldPopulateCalypsoCard)
{
    setUp();

    /*
     * EF LIST
     * C028
     * C106 2001 07 02 1D 01
     * C106 20FF 09 01 1D 04
     * C106 F123 10 04 F3 F4
     * C106 F124 11 08 F3 F4
     * C106 F125 1F 09 F3 F4
     */
    const auto cardCardRequest = createCardRequest({CARD_GET_DATA_EF_LIST_CMD});
    const auto cardCardResponse = createCardResponse({CARD_GET_DATA_EF_LIST_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    ASSERT_EQ(calypsoCard->getFiles().size(), 0);

    cardTransactionManager->prepareGetData(GetDataTag::EF_LIST);
    cardTransactionManager->processCommands();

    ASSERT_EQ(calypsoCard->getFiles().size(), 5);

    const auto fileHeader07 = calypsoCard->getFileBySfi(0x07)->getHeader();
    ASSERT_EQ(fileHeader07->getLid(), 0x2001);
    ASSERT_EQ(fileHeader07->getEfType(), ElementaryFile::Type::LINEAR);
    ASSERT_EQ(fileHeader07->getRecordSize(), 0x1D);
    ASSERT_EQ(fileHeader07->getRecordsNumber(), 0x01);

    const auto fileHeader09 = calypsoCard->getFileBySfi(0x09)->getHeader();
    ASSERT_EQ(fileHeader09->getLid(), 0x20FF);
    ASSERT_EQ(fileHeader09->getEfType(), ElementaryFile::Type::BINARY);
    ASSERT_EQ(fileHeader09->getRecordSize(), 0x1D);
    ASSERT_EQ(fileHeader09->getRecordsNumber(), 0x04);

    const auto fileHeader10 = calypsoCard->getFileBySfi(0x10)->getHeader();
    ASSERT_EQ(fileHeader10->getLid(), 0xF123);
    ASSERT_EQ(fileHeader10->getEfType(), ElementaryFile::Type::CYCLIC);
    ASSERT_EQ(fileHeader10->getRecordSize(), 0xF3);
    ASSERT_EQ(fileHeader10->getRecordsNumber(), 0xF4);

    const auto fileHeader11 = calypsoCard->getFileBySfi(0x11)->getHeader();
    ASSERT_EQ(fileHeader11->getLid(), 0xF124);
    ASSERT_EQ(fileHeader11->getEfType(), ElementaryFile::Type::SIMULATED_COUNTERS);
    ASSERT_EQ(fileHeader11->getRecordSize(), 0xF3);
    ASSERT_EQ(fileHeader11->getRecordsNumber(), 0xF4);

    const auto fileHeader1F = calypsoCard->getFileBySfi(0x1F)->getHeader();
    ASSERT_EQ(fileHeader1F->getLid(), 0xF125);
    ASSERT_EQ(fileHeader1F->getEfType(), ElementaryFile::Type::COUNTERS);
    ASSERT_EQ(fileHeader1F->getRecordSize(), 0xF3);
    ASSERT_EQ(fileHeader1F->getRecordsNumber(), 0xF4);

    ASSERT_EQ(calypsoCard->getFileByLid(0x20FF), calypsoCard->getFileBySfi(0x09));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareGetData_whenGetDataTagIsTRACEABILITY_INFORMATION_shouldPopulateCalypsoCard)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD});
    const auto cardCardResponse = createCardResponse({CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareGetData(GetDataTag::TRACEABILITY_INFORMATION);

    ASSERT_EQ(calypsoCard->getTraceabilityInformation().size(), 0);

    cardTransactionManager->processCommands();

    ASSERT_EQ(calypsoCard->getTraceabilityInformation(),
              HexUtil::toByteArray("00112233445566778899"));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareGetData_whenGetDataTagIsFCI_shouldPrepareSelectFileApduWithTagFCI)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_GET_DATA_FCI_CMD});
    const auto cardCardResponse = createCardResponse({CARD_GET_DATA_FCI_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareGetData(GetDataTag::FCI_FOR_CURRENT_DF);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecord(31, 1), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecord(FILE7, -1), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecord(FILE7, 251), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_READ_REC_SFI7_REC1_CMD});
    const auto cardCardResponse = createCardResponse({CARD_READ_REC_SFI7_REC1_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadRecords_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecords(31, 1, 1, 1), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadRecords_whenFromRecordNumberIs0_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecords(FILE7, 0, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecords_whenFromRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecords(FILE7, 251, 251, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecords_whenToRecordNumberIsLessThanFromRecordNumber_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecords(FILE7, 2, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecords_whenToRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecords(FILE7, 1, 251, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecords_whenNbRecordsToReadMultipliedByRecSize2IsLessThanPayLoad_shouldPrepareOneCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_READ_RECORDS_FROM1_TO2_CMD});
    const auto cardCardResponse = createCardResponse({CARD_READ_RECORDS_FROM1_TO2_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
    //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillOnce(Return(7));

    cardTransactionManager->prepareReadRecords( 1, 1, 2, 1);
    cardTransactionManager->processCommands();

    ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(1), HexUtil::toByteArray("11"));
    ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(2), HexUtil::toByteArray("22"));

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareReadRecords_whenNbRecordsToReadMultipliedByRecSize2IsGreaterThanPayLoad_shouldPrepareMultipleCommands)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_READ_RECORDS_FROM1_TO2_CMD,
//                                                     CARD_READ_RECORDS_FROM3_TO4_CMD,
//                                                     CARD_READ_RECORDS_FROM5_TO5_CMD});
//     const auto cardCardResponse = createCardResponse({CARD_READ_RECORDS_FROM1_TO2_RSP,
//                                                       CARD_READ_RECORDS_FROM3_TO4_RSP,
//                                                       CARD_READ_RECORDS_FROM5_TO5_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillOnce(Return(7));

//     cardTransactionManager->prepareReadRecords(1, 1, 5, 1);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(1), HexUtil::toByteArray("11"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(2), HexUtil::toByteArray("22"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(3), HexUtil::toByteArray("33"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(4), HexUtil::toByteArray("44"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(5), HexUtil::toByteArray("55"));

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadCounter(31, 1), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,prepareAppendRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareAppendRecord(31, std::vector<uint8_t>(3)),
                 IllegalArgumentException);

    tearDown();
}

// C++: vector reference, cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest,prepareAppendRecord_whenRecordDataIsNull_shouldThrowIAE)
// {
//     setUp();
//
//     EXPECT_THROW(cardTransactionManager->prepareAppendRecord(FILE7, null), IllegalArgumentException);
//
//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,prepareUpdateRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateRecord(31, 1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareUpdateRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateRecord(FILE7, 251, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

// C++: vector reference, cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest,prepareUpdateRecord_whenRecordDataIsNull_shouldThrowIAE)
// {
//     setUp();
//
//     EXPECT_THROW(cardTransactionManager->prepareUpdateRecord(FILE7, 1, null),
//                  IllegalArgumentException);
//
//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareWriteRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareWriteRecord(31, 1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareWriteRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareWriteRecord(FILE7, 251, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenProductTypeIsNotPrimeRev3_shouldThrowUOE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(nullptr),
                 UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenDataIsNull_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(nullptr), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenDataIsNotInstanceOfInternalAdapter_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(
                     std::make_shared<SearchCommandDataMock>()),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenSfiIsNegative_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSfi(-1).setSearchData(std::vector<uint8_t>(1));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenSfiGreaterThanSfiMax_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSfi(31).setSearchData(std::vector<uint8_t>(1));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenRecordNumberIs0_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->startAtRecord(0).setSearchData(std::vector<uint8_t>(1));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->startAtRecord(251).setSearchData(std::vector<uint8_t>(1));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setOffset(-1).setSearchData(std::vector<uint8_t>(1));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenOffsetIsGreaterThan249_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setOffset(250).setSearchData(std::vector<uint8_t>(1));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenSearchDataIsNotSet_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

// C++: search data comes as a vector reference, cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenSearchDataIsNull_shouldThrowIAE)
// {
//     setUp();

//     auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
//     data->setSearchData(null);

//     EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenSearchDataIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>(0));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenSearchDataLengthIsGreaterThan250MinusOffset0_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>(251));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenSearchDataLengthIsGreaterThan249MinusOffset1_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setOffset(1).setSearchData(std::vector<uint8_t>(250));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenMaskLengthIsGreaterThanSearchDataLength_shouldThrowIAE)
{
    setUp();

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>(1)).setMask(std::vector<uint8_t>(2));

    EXPECT_THROW(cardTransactionManager->prepareSearchRecords(data), IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenUsingDefaultParameters_shouldPrepareDefaultCommand)
{
    setUp();

    auto cardCardRequest =
        createCardRequest({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_CMD});
    auto cardCardResponse =
        createCardResponse({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>({0x12, 0x34}));

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands();

    ASSERT_TRUE(Arrays::equals(data->getMatchingRecordNumbers(), {4, 6}));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenSetAllParameters_shouldPrepareCustomCommand)
{
    setUp();

    auto cardCardRequest =
        createCardRequest({CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD});
    auto cardCardResponse =
        createCardResponse({CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSfi(4)
         .startAtRecord(2)
         .setOffset(3)
         .enableRepeatedOffset()
         .setSearchData(std::vector<uint8_t>({0x12, 0x34}))
         .fetchFirstMatchingResult();

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands();


    ASSERT_TRUE(Arrays::equals(data->getMatchingRecordNumbers(), {4, 6}));
    ASSERT_EQ(calypsoCard->getFileBySfi(4)->getData()->getContent(4),
              HexUtil::toByteArray("112233123456"));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenNoMask_shouldFillMaskWithFFh)
{
    setUp();

    auto cardCardRequest =
        createCardRequest({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_CMD});
    auto cardCardResponse =
        createCardResponse({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_FFFF_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>({0x12, 0x34}));

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands();

    ASSERT_TRUE(Arrays::equals(data->getMatchingRecordNumbers(), {4, 6}));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSearchRecords_whenPartialMask_shouldRightPadMaskWithFFh)
{
    setUp();

    auto cardCardRequest =
        createCardRequest({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_CMD});
    auto cardCardResponse =
        createCardResponse({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_56FF_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>({0x12, 0x34})).setMask(std::vector<uint8_t>({0x56}));

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands();

    ASSERT_TRUE(Arrays::equals(data->getMatchingRecordNumbers(), {4, 6}));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSearchRecords_whenFullMask_shouldUseCompleteMask)
{
    setUp();

    auto cardCardRequest =
        createCardRequest({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_CMD});
    auto cardCardResponse =
        createCardResponse({CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NOFETCH_1234_5677_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    auto data = CalypsoExtensionService::getInstance()->createSearchCommandData();
    data->setSearchData(std::vector<uint8_t>({0x12, 0x34})).setMask(std::vector<uint8_t>({0x56, 0x77}));

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands();

    ASSERT_TRUE(Arrays::equals(data->getMatchingRecordNumbers(), {4, 6}));

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenProductTypeIsNotPrimeRev3OrLight_shouldThrowUOE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 1, 1),
                 UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenSfiIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(-1, 1, 1, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(31, 1, 1, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenFromRecordNumberIsZero_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 0, 1, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenFromRecordNumberGreaterThan250_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 251, 251, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
      prepareReadRecordsPartially_whenToRecordNumberLessThanFromRecordNumber_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially( 1, 2, 1, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenToRecordNumberGreaterThan250MinusFromRecordNumber_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially( 1, 1, 251, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, -1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenOffsetGreaterThan249_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 250, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenNbBytesToReadIsZero_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 1, 0),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
      prepareReadRecordsPartially_whenNbBytesToReadIsGreaterThan250MinusOffset_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 3, 248),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadRecordsPartially_whenNbRecordsToReadMultipliedByNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand)
{
    setUp();

    auto cardCardRequest =
        createCardRequest({CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_CMD});
    auto cardCardResponse =
        createCardResponse({CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
    //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillAlways(Return(3));

    cardTransactionManager->prepareReadRecordsPartially(1, 1, 2, 3, 1);
    cardTransactionManager->processCommands();

    ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(1),
              HexUtil::toByteArray("00000011"));
    ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(2),
              HexUtil::toByteArray("00000022"));

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareReadRecordsPartially_whenNbRecordsToReadMultipliedByNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands)
// {
//     setUp();

//     auto cardCardRequest = createCardRequest({CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_CMD,
//                                               CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_CMD,
//                                               CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_CMD});
//     auto cardCardResponse = createCardResponse({CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NBBYTE1_RSP,
//                                                 CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NBBYTE1_RSP,
//                                                 CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NBBYTE1_RSP});



//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillAlways(Return(2));

//     cardTransactionManager->prepareReadRecordsPartially(1, 1, 5, 3, 1);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(1),
//               HexUtil::toByteArray("00000011"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(2),
//               HexUtil::toByteArray("00000022"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(3),
//               HexUtil::toByteArray("00000033"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(4),
//               HexUtil::toByteArray("00000044"));
//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(5),
//               HexUtil::toByteArray("00000055"));

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,
     prepareUpdateBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_LIGHT);

    EXPECT_THROW(cardTransactionManager->prepareUpdateBinary(1, 1, std::vector<uint8_t>(1)),
                 UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadBinary_whenSfiIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadBinary(-1, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadBinary(31, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadBinary(1, -1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadBinary(1, 32768, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareReadBinary(1, 1, 0),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareReadBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
                                                    CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD});
    const auto cardCardResponse = createCardResponse({CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP,
                                                      CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareReadBinary(1, 256, 1);
    cardTransactionManager->processCommands();

    const auto content = calypsoCard->getFileBySfi(1)->getData()->getContent();

    ASSERT_EQ(content.size(), 257);
    ASSERT_TRUE(Arrays::startsWith(content, HexUtil::toByteArray("1100")));
    ASSERT_TRUE(Arrays::endsWith(content, HexUtil::toByteArray("0066")));

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareReadBinary_whenNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD});
//     const auto cardCardResponse = createCardResponse({CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillAlways(Return(2));

//     cardTransactionManager->prepareReadBinary(1, 0, 1);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(), HexUtil::toByteArray("11"));

//     tearDown();
// }

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareReadBinary_whenNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD});
//     const auto cardCardResponse = createCardResponse({CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillAlways(Return(2));

//     cardTransactionManager->prepareReadBinary(1, 0, 1);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(), HexUtil::toByteArray("11"));

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareUpdateBinary_whenSfiIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateBinary(-1, 1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareUpdateBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateBinary(31, 1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareUpdateBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateBinary(1, -1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareUpdateBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateBinary(1, 32768, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

// C++: data comes as a vector reference, cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareUpdateBinary_whenDataIsNull_shouldThrowIAE)
// {
//     setUp();

//     EXPECT_THROW(cardTransactionManager->prepareUpdateBinary( 1, 1, null),
//                  IllegalArgumentException);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareUpdateBinary_whenDataIsEmpty_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareUpdateBinary(1, 1, std::vector<uint8_t>(0)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareUpdateBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
                                                    CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD});
    const auto cardCardResponse = createCardResponse({CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP,
                                                      SW1SW2_OK_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareUpdateBinary(1, 256, HexUtil::toByteArray("66"));
    cardTransactionManager->processCommands();

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareUpdateBinary_whenDataLengthIsLessThanPayLoad_shouldPrepareOneCommand)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD});
//     const auto cardCardResponse = createCardResponse({SW1SW2_OK_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

//     cardTransactionManager->prepareUpdateBinary(1, 4, HexUtil::toByteArray("55"));
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(),
//               HexUtil::toByteArray("0000000055"));

//     tearDown();
// }

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareUpdateBinary_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD,
//                                                     CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD,
//                                                     CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD});
//     const auto cardCardResponse = createCardResponse({SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

//     cardTransactionManager->prepareUpdateBinary(1, 0, HexUtil::toByteArray("1122334455"));
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(),
//               HexUtil::toByteArray("1122334455"));

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,
     prepareWriteBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_LIGHT);

    EXPECT_THROW(cardTransactionManager->prepareWriteBinary(1, 1, std::vector<uint8_t>(1)),
                 UnsupportedOperationException);

    tearDown();
}

// C++: sfi is unsigned, cannot be negative, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareWriteBinary_whenSfiIsNegative_shouldThrowIAE)
// {
//     setUp();

//     EXPECT_THROW(cardTransactionManager->prepareWriteBinary(-1, 1, std::vector<uint8_t>(1)),
//                  IllegalArgumentException);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareWriteBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareWriteBinary(31, 1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareWriteBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareWriteBinary(1, -1, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareWriteBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareWriteBinary(1, 32768, std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

// C++: data comes as a vector reference, cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareWriteBinary_whenDataIsNull_shouldThrowIAE)
// {
//     setUp();

//     EXPECT_THROW(cardTransactionManager->prepareWriteBinary(1, 1, nullptr),
//                  IllegalArgumentException);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareWriteBinary_whenDataIsEmpty_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareWriteBinary(1, 1, std::vector<uint8_t>(0)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareWriteBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
                                                    CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD});
    const auto cardCardResponse = createCardResponse({CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP,
                                                      SW1SW2_OK_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareWriteBinary(1, 256, HexUtil::toByteArray("66"));
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareWriteBinary_whenDataLengthIsLessThanPayLoad_shouldPrepareOneCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD});
    const auto cardCardResponse = createCardResponse({SW1SW2_OK_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
    //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    cardTransactionManager->prepareWriteBinary(1, 4, HexUtil::toByteArray("55"));
    cardTransactionManager->processCommands();

    ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(),
              HexUtil::toByteArray("0000000055"));

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest
//      prepareWriteBinary_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD,
//                                                     CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD,
//                                                     CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD});
//     const auto cardCardResponse = createCardResponse({SW1SW2_OK_RSP, SW1SW2_OK_RSP, SW1SW2_OK_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

//     cardTransactionManager->prepareWriteBinary(1, 0, HexUtil::toByteArray("1122334455"));
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(calypsoCard->getFileBySfi(1)->getData()->getContent(),
//               HexUtil::toByteArray("1122334455"));

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounter(31, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareIncreaseCounter_whenValueIsLessThan0_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounter(FILE7, 1, -1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounter(FILE7, 1, 16777216),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounter(FILE7, 84, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounter_whenParametersAreCorrect_shouldAddDecreaseCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_INCREASE_SFI11_CNT1_100U_CMD});
    const auto cardCardResponse = createCardResponse({CARD_INCREASE_SFI11_CNT1_8821U_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
    //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    cardTransactionManager->prepareIncreaseCounter(1, 1, 100);
    cardTransactionManager->processCommands();

    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 8821);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounter(31, 1, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareDecreaseCounter_whenValueIsLessThan0_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounter(FILE7, 1, -1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounter(FILE7, 1, 16777216),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounter(FILE7, 84, 1),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounter_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_DECREASE_SFI10_CNT1_100U_CMD});
    const auto cardCardResponse = createCardResponse({CARD_DECREASE_SFI10_CNT1_4286U_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
    //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    cardTransactionManager->prepareDecreaseCounter(1, 1, 100);
    cardTransactionManager->processCommands();

    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 4286);

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareIncreaseCounters_whenCardIsLowerThanPrime3__shouldAddMultipleIncreaseCommands)
// {
//     setUp();

//     //EXPECT_CALL(*calypsoCard, getProductType()).WillOnce(Return(CalypsoCard::ProductType::BASIC));

//     const auto cardCardRequest = createCardRequest({CARD_INCREASE_SFI11_CNT1_100U_CMD});
//     const auto cardCardResponse = createCardResponse({CARD_INCREASE_SFI11_CNT1_8821U_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

//     std::map<const int, const int> counterNumberToIncValueMap;
//     counterNumberToIncValueMap.insert({1, 100});

//     cardTransactionManager->prepareIncreaseCounters(1, counterNumberToIncValueMap);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 8821);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounters_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 1});

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounters(31, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareIncreaseCounters_whenValueIsLessThan0_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, -1});

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounters(FILE7, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounters_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({84, 1});

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounters(FILE7, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounters_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 16777216});

    EXPECT_THROW(cardTransactionManager->prepareIncreaseCounters(FILE7, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareIncreaseCounters_whenParametersAreCorrect_shouldAddIncreaseMultipleCommand)
{
    setUp();

    const auto cardCardRequest =
        createCardRequest({CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD});
    const auto cardCardResponse =
        createCardResponse({CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({3, 3});
    counterNumberToIncValueMap.insert({1, 1});
    counterNumberToIncValueMap.insert({2, 2});

    cardTransactionManager->prepareIncreaseCounters(1, counterNumberToIncValueMap);
    cardTransactionManager->processCommands();

    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 0x11);
    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(2)), 0x22);
    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(3)), 0x33);

    tearDown();
}

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareIncreaseCounters_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands)
// {
//     setUp();

//     const auto cardCardRequest = createCardRequest({CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD,
//                                                     CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD});
//     const auto cardCardResponse = createCardResponse({CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP,
//                                                       CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard->getPayloadCapacity()).WillRepeatedly(Return(9));

//     std::map<const int, const int> counterNumberToIncValueMap;
//     counterNumberToIncValueMap.insert({1, 1});
//     counterNumberToIncValueMap.insert({2, 2});
//     counterNumberToIncValueMap.insert({3, 3});

//     cardTransactionManager->prepareIncreaseCounters(1, counterNumberToIncValueMap);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 0x11);
//     ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(2)), 0x22);
//     ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(3)), 0x33);

//     tearDown();
// }

// C++: that test requires mocking a final class, doesn't work
// TEST(CardTransactionManagerAdapterTest,
//      prepareDecreaseCounters_whenCardIsLowerThanPrime3_shouldThrowUOE)
// {
//     setUp();

//     //EXPECT_CALL(*calypsoCard, getProductType()).WillRepeatedly(Return(CalypsoCard::ProductType::BASIC));

//     const auto cardCardRequest = createCardRequest({CARD_DECREASE_SFI10_CNT1_100U_CMD});
//     const auto cardCardResponse = createCardResponse({CARD_DECREASE_SFI10_CNT1_4286U_RSP});

//     EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));
//     //EXPECT_CALL(*calypsoCard->getPayloadCapacity()).WillRepeatedly(Return(9));

//     std::map<const int, const int> counterNumberToDecValueMap;
//     counterNumberToDecValueMap.insert({1, 100});

//     cardTransactionManager->prepareDecreaseCounters(1, counterNumberToDecValueMap);
//     cardTransactionManager->processCommands();

//     ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 4286);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounters_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 1});

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounters(31, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareDecreaseCounters_whenValueIsLessThan0_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, -1});

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounters(FILE7, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounters_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({84, 1});

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounters(FILE7, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounters_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    setUp();

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 16777216});

    EXPECT_THROW(cardTransactionManager->prepareDecreaseCounters(FILE7, counterNumberToIncValueMap),
                 IllegalArgumentException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareDecreaseCounters_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand)
{
    setUp();

    const auto ocardCardRequest =
        createCardRequest({CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD});
    const auto cardCardResponse =
        createCardResponse({CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    std::map<const int, const int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({2, 0x22});
    counterNumberToIncValueMap.insert({8, 0x88});
    counterNumberToIncValueMap.insert({1, 0x11});

    cardTransactionManager->prepareDecreaseCounters( 1, counterNumberToIncValueMap);
    cardTransactionManager->processCommands();

    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1)), 0x111);
    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(2)), 0x222);
    ASSERT_EQ(*(calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(8)), 0x888);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSetCounter_whenCounterNotPreviouslyRead_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareSetCounter(FILE7, 1, 1), IllegalStateException);

    tearDown();
  }

TEST(CardTransactionManagerAdapterTest,
     prepareCheckPinStatus_whenPinFeatureIsNotAvailable_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareCheckPinStatus(), UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareCheckPinStatus_whenPinFeatureIsAvailable_shouldPrepareCheckPinStatusApdu)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    const auto cardCardRequest = createCardRequest({CARD_CHECK_PIN_CMD});
    const auto cardCardResponse = createCardResponse({SW1SW2_OK});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareCheckPinStatus();
    cardTransactionManager->processCommands();

    tearDown();
}

// C++: SvOperation tag cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareSvGet_whenSvOperationNull_shouldThrowIAE)
// {
//     setUp();

//     EXPECT_THROW(cardTransactionManager->prepareSvGet(nullptr, SvAction::DO),
//                  IllegalArgumentException);

//     tearDown();
// }

// C++: SvAction tag cannot be null, test does not apply
// TEST(CardTransactionManagerAdapterTest, prepareSvGet_whenSvActionNull_shouldThrowIAE)
// {
//     setUp();

//     EXPECT_THROW(cardTransactionManager->prepareSvGet(SvOperation::DEBIT, nullptr),
//                  IllegalArgumentException);

//     tearDown();
// }

TEST(CardTransactionManagerAdapterTest, prepareSvGet_whenSvOperationNotAvailable_shouldThrowUOE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareSvGet(SvOperation::DEBIT, SvAction::DO),
                 UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSvGet_whenSvOperationDebit_shouldPrepareSvGetDebitApdu)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    const auto cardCardRequest = createCardRequest({CARD_SV_GET_DEBIT_CMD});
    const auto cardCardResponse = createCardResponse({CARD_SV_GET_DEBIT_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSvGet(SvOperation::DEBIT, SvAction::DO);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSvGet_whenSvOperationReload_shouldPrepareSvGetReloadApdu)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    const auto cardCardRequest = createCardRequest({CARD_SV_GET_RELOAD_CMD});
    const auto cardCardResponse = createCardResponse({CARD_SV_GET_RELOAD_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSvGet(SvOperation::RELOAD, SvAction::DO);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSvGet_whenSvOperationReloadWithPrimeRev2_shouldPrepareSvGetReloadApdu)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE);

    const auto cardCardResponse = createCardResponse({CARD_SV_GET_RELOAD_RSP});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareSvGet(SvOperation::RELOAD, SvAction::DO);
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSvReload_whenNoSvGetPreviouslyExecuted_shouldThrowISE)
{
    setUp();

    const auto samCardRequest = createCardRequest({SAM_SV_CHECK_CMD});
    const auto samCardResponse = createCardResponse({SW1SW2_OK});

    ON_CALL(*samReader, transmitCardRequest(_, _)).WillByDefault(Return(samCardResponse));

    EXPECT_THROW(cardTransactionManager->prepareSvReload(1), IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSvDebit_whenNoSvGetPreviouslyExecuted_shouldThrowISE)
{
    setUp();

    const auto samCardRequest = createCardRequest({SAM_SV_CHECK_CMD});
    const auto samCardResponse = createCardResponse({SW1SW2_OK});

    ON_CALL(*samReader, transmitCardRequest(_, _)).WillByDefault(Return(samCardResponse));

    EXPECT_THROW(cardTransactionManager->prepareSvDebit(1), IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareSvReadAllLogs_whenPinFeatureIsNotAvailable_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareSvReadAllLogs(), UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareSvReadAllLogs_whenNotAnSVApplication_shouldThrowISE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    EXPECT_THROW(cardTransactionManager->prepareSvReadAllLogs(), UnsupportedOperationException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareInvalidate_whenCardIsInvalidated_shouldThrowISE)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED);

    EXPECT_THROW(cardTransactionManager->prepareInvalidate(), IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareInvalidate_whenCardIsNotInvalidated_prepareInvalidateApdu)
{
    setUp();

    const auto cardCardRequest = createCardRequest({CARD_INVALIDATE_CMD});
    const auto cardCardResponse = createCardResponse({SW1SW2_OK});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareInvalidate();
    cardTransactionManager->processCommands();

    tearDown();
}

TEST(CardTransactionManagerAdapterTest, prepareRehabilitate_whenCardIsNotInvalidated_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(cardTransactionManager->prepareRehabilitate(), IllegalStateException);

    tearDown();
}

TEST(CardTransactionManagerAdapterTest,
     prepareRehabilitate_whenCardIsInvalidated_prepareInvalidateApdu)
{
    setUp();

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED);

    const auto cardCardRequest = createCardRequest({CARD_REHABILITATE_CMD});
    const auto cardCardResponse = createCardResponse({SW1SW2_OK});

    EXPECT_CALL(*cardReader, transmitCardRequest(_, _)).WillOnce(Return(cardCardResponse));

    cardTransactionManager->prepareRehabilitate();
    cardTransactionManager->processCommands();

    tearDown();
}
