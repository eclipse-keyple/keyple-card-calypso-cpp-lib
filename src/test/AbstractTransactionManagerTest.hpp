/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#pragma once

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keypop/card/spi/ApduRequestSpi.hpp"
#include "keypop/reader/ChannelControl.hpp"

#include "TestDtoAdapters.hpp"

#include "mock/CalypsoCardAdapterMock.hpp"
#include "mock/ReaderMock.hpp"

using keyple::card::calypso::CalypsoCardAdapter;
using keyple::card::calypso::DtoAdapters;
using keypop::card::spi::ApduRequestSpi;

using testing::_;
using testing::Return;

class AbstractTransactionManagerTest {
public:
    static keypop::reader::ChannelControl CHANNEL_CONTROL_KEEP_OPEN;
    static keypop::reader::ChannelControl CHANNEL_CONTROL_CLOSE_AFTER;

    static const std::string CARD_SERIAL_NUMBER;
    static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3;
    static const std::string
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED;
    static const std::string
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN;
    static const std::string
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE;
    static const std::string
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED_WITH_STORED_VALUE;
    static const std::string SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2;
    static const std::string
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE;
    static const std::string
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED;
    static const std::string SELECT_APPLICATION_RESPONSE_LIGHT;

    static const std::string PIN_OK;
    static const std::vector<std::uint8_t> PIN_OK_BYTES;
    static const std::string NEW_PIN;
    static const std::vector<std::uint8_t> NEW_PIN_BYTES;
    static const std::string CIPHER_PIN_UPDATE_OK;
    static const std::string PIN_5_DIGITS;
    static const std::vector<std::uint8_t> PIN_5_DIGITS_BYTES;
    static const std::uint8_t PIN_CIPHERING_KEY_KIF;
    static const std::uint8_t PIN_CIPHERING_KEY_KVC;

    static const std::uint8_t FILE7;
    static const std::uint8_t FILE8;
    static const std::uint8_t FILE10;
    static const int RECORD_SIZE;

    static const std::string SW_9000;
    static const std::string SW_6200;
    static const std::string SW_6985;
    static const std::string SW_INCORRECT_SIGNATURE;
    static const std::string SAM_CHALLENGE;
    static const std::string SAM_CHALLENGE_EXTENDED;
    static const std::string CARD_CHALLENGE;
    static const std::string SAM_SIGNATURE;
    static const std::string CARD_SIGNATURE;

    static const std::string FILE7_REC1_29B;
    static const std::string FILE7_REC2_29B;
    static const std::string FILE8_REC1_29B;

    static const std::string FILE10_REC1_COUNTER;

    static const std::string ACCESS_CONDITIONS_1234;
    static const std::string KEY_INDEXES_1234;
    static const std::string CIPHERED_KEY;

    static const std::string CARD_OPEN_SECURE_SESSION_CMD;
    static const std::string KIF;
    static const std::string KVC;
    static const std::string CARD_OPEN_SECURE_SESSION_DATA_OUT;
    static const std::string CARD_OPEN_SECURE_SESSION_RSP;
    static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD;
    static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT;
    static const std::string CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP;
    static const std::string CARD_OPEN_SECURE_SESSION_EXTENDED_CMD;

    static const std::string CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT;
    static const std::string CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT_2;
    static const std::string CARD_OPEN_SECURE_SESSION_EXTENDED_RSP;
    static const std::string
        CARD_OPEN_SECURE_SESSION_EXTENDED_NOT_SUPPORTED_RSP;
    static const std::string CARD_CLOSE_SECURE_SESSION_CMD;
    static const std::string CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD;
    static const std::string CARD_SIGNATURE_EXTENDED;
    static const std::string CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP;
    static const std::string CARD_CLOSE_SECURE_SESSION_RSP;
    static const std::string CARD_ABORT_SECURE_SESSION_CMD;

    static const std::string CARD_READ_REC_SFI1_REC2_CMD;
    static const std::string CARD_READ_REC_SFI1_REC2_RSP;
    static const std::string CARD_READ_REC_SFI1_REC4_CMD;
    static const std::string CARD_READ_REC_SFI1_REC4_RSP;
    static const std::string CARD_READ_REC_SFI1_REC5_CMD;
    static const std::string CARD_READ_REC_SFI1_REC5_RSP;
    static const std::string CARD_READ_REC_SFI7_REC1_CMD;
    static const std::string CARD_READ_REC_SFI7_REC1_L29_CMD;
    static const std::string CARD_READ_REC_SFI7_REC1_RSP;
    static const std::string CARD_READ_REC_SFI8_REC1_L29_CMD;
    static const std::string CARD_READ_REC_SFI8_REC1_RSP;
    static const std::string CARD_READ_REC_SFI10_REC1_CMD;
    static const std::string CARD_READ_REC_SFI10_REC1_RSP;
    static const std::string CARD_READ_RECORDS_FROM1_TO2_CMD;
    static const std::string CARD_READ_RECORDS_FROM1_TO2_RSP;
    static const std::string CARD_READ_RECORDS_FROM3_TO4_CMD;
    static const std::string CARD_READ_RECORDS_FROM3_TO4_RSP;
    static const std::string CARD_READ_RECORDS_FROM5_TO5_CMD;
    static const std::string CARD_READ_RECORDS_FROM5_TO5_RSP;
    static const std::string CARD_DECREASE_SFI10_CNT1_100U_CMD;
    static const std::string CARD_DECREASE_SFI10_CNT1_4286U_RSP;
    static const std::string CARD_INCREASE_SFI11_CNT1_100U_CMD;
    static const std::string CARD_INCREASE_SFI11_CNT1_8821U_RSP;
    static const std::string CARD_INCREASE_SFI11_CNT1_100U_CMD_CASE3;
    static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD;
    static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP;
    static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD;
    static const std::string CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP;
    static const std::string CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD;
    static const std::string CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP;
    static const std::string CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD;
    static const std::string
        CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_CMD;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_RSP;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_56FF_CMD;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_56FF_RSP;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_5677_CMD;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_5677_RSP;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD;
    static const std::string
        CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP;
    static const std::string
        CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_CMD;
    static const std::string
        CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_RSP;
    static const std::string
        CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NB_BYTE1_CMD;
    static const std::string
        CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NB_BYTE1_RSP;
    static const std::string
        CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NB_BYTE1_CMD;
    static const std::string
        CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NB_BYTE1_RSP;
    static const std::string CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD;
    static const std::string CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP;
    static const std::string CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD;
    static const std::string CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP;
    static const std::string CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD;
    static const std::string CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD;
    static const std::string CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD;
    static const std::string CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD;
    static const std::string CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD;
    static const std::string CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD;
    static const std::string CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD;
    static const std::string CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD;

    static const std::string CARD_SELECT_FILE_CURRENT_CMD;
    static const std::string CARD_SELECT_FILE_FIRST_CMD;
    static const std::string CARD_SELECT_FILE_NEXT_CMD;
    static const std::string CARD_SELECT_FILE_1234_CMD;
    static const std::string CARD_SELECT_FILE_1234_RSP;
    static const std::string CARD_SELECT_FILE_1234_CMD_PRIME_REV2;
    static const std::string CARD_SELECT_FILE_1234_RSP_PRIME_REV2;

    static const std::string CARD_GET_DATA_FCI_CMD;
    static const std::string CARD_GET_DATA_FCP_CMD;
    static const std::string CARD_GET_DATA_EF_LIST_CMD;
    static const std::string CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD;
    static const std::string CARD_GET_DATA_FCI_RSP;
    static const std::string CARD_GET_DATA_FCP_RSP;
    static const std::string CARD_GET_DATA_EF_LIST_RSP;
    static const std::string CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP;

    static const std::string CARD_VERIFY_PIN_PLAIN_OK_CMD;
    static const std::string CARD_CHECK_PIN_CMD;
    static const std::string CARD_CHANGE_PIN_CMD;
    static const std::string CARD_CHANGE_PIN_PLAIN_CMD;
    static const std::string CARD_CHANGE_PIN_RSP;
    static const std::string CARD_CHANGE_PIN_PLAIN_RSP;

    static const std::string SV_R_PREV_SIGN_LO;
    static const std::string SV_R_CHALLENGE_OUT;
    static const std::string SV_R_PREV_SIGN_LO_EXT;
    static const std::string SV_D_PREV_SIGN_LO_EXT;
    static const std::string SV_R_CHALLENGE_OUT_EXT;
    static const std::string SV_D_CHALLENGE_OUT_EXT;
    static const std::string SV_R_CURRENT_KVC;
    static const std::string SV_R_TNUM;
    static const std::string SV_R_BALANCE;
    static const std::string SV_R_LOG_DATE;
    static const std::string SV_R_LOG_FREE1;
    static const std::string SV_R_LOG_KVC;
    static const std::string SV_R_LOG_FREE2;
    static const std::string SV_R_LOG_BALANCE;
    static const std::string SV_R_LOG_AMOUNT;
    static const std::string SV_R_LOG_TIME;
    static const std::string SV_R_LOG_SAM_ID;
    static const std::string SV_R_LOG_SAM_TNUM;
    static const std::string SV_R_LOG_SV_TNUM;
    static const std::string SV_D_CURRENT_KVC;
    static const std::string SV_D_TNUM;
    static const std::string SV_D_PREV_SIGN_LO;
    static const std::string SV_D_CHALLENGE_OUT;
    static const std::string SV_D_BALANCE;
    static const std::string SV_D_LOG_AMOUNT;
    static const std::string SV_D_LOG_DATE;
    static const std::string SV_D_LOG_TIME;
    static const std::string SV_D_LOG_KVC;
    static const std::string SV_D_LOG_SAM_ID;
    static const std::string SV_D_LOG_SAM_TNUM;
    static const std::string SV_D_LOG_BALANCE;
    static const std::string SV_D_LOG_SV_TNUM;
    static const std::string CARD_SV_GET_DEBIT_CMD;
    static const std::string CARD_SV_GET_DEBIT_EXT_CMD;
    static const std::string CARD_SV_GET_DEBIT_RSP;
    static const std::string CARD_SV_GET_DEBIT_EXT_RSP;
    static const std::string CARD_SV_GET_RELOAD_CMD;
    static const std::string CARD_SV_GET_RELOAD_EXT_CMD;
    static const std::string CARD_PRIME_REV2_SV_GET_RELOAD_CMD;
    static const std::string CARD_SV_GET_RELOAD_RSP;
    static const std::string CARD_SV_GET_RELOAD_EXT_RSP;

    static const std::string CARD_INVALIDATE_CMD;
    static const std::string CARD_REHABILITATE_CMD;

    static const std::string CARD_GET_CHALLENGE_CMD;
    static const std::string CARD_GET_CHALLENGE_RSP;

    static const std::string CARD_CHANGE_KEY_CMD;
    static const std::string SAM_SIGNATURE_EXTENDED;
    static const std::string CARD_MSS_AUTHENTICATION_ENCRYPTION_CMD;
    static const std::string CARD_MSS_AUTHENTICATION_ENCRYPTION_RSP;
    static const std::string CARD_MSS_AUTHENTICATION_CMD;
    static const std::string CARD_MSS_AUTHENTICATION_RSP;
    static const std::string CARD_MSS_ENCRYPTION_CMD;
    static const std::string CARD_MSS_CMD;
    static const std::string CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD;
    static const std::string CARD_READ_REC_ENCRYPTED_SFI1_REC1_RSP;
    static const std::string CARD_READ_REC_DECRYPTED_SFI1_REC1_RSP;
    static const std::string CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD;
    static const std::string CARD_READ_REC_ENCRYPTED_SFI1_REC3_RSP;
    static const std::string CARD_READ_REC_DECRYPTED_SFI1_REC3_RSP;
    static const std::string CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD;
    static const std::string CARD_READ_REC_ENCRYPTED_SFI1_REC6_RSP;
    static const std::string CARD_READ_REC_DECRYPTED_SFI1_REC6_RSP;
    static const std::string CARD_UPDATE_REC_SFI1_REC1_CMD;
    static const std::string CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_CMD;
    static const std::string CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_RSP;
    static const std::string CARD_UPDATE_REC_SFI1_REC2_CMD;
    static const std::string CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_CMD;
    static const std::string CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_RSP;

    /* Content */

    std::shared_ptr<ReaderMock> cardReader;
    std::shared_ptr<CalypsoCardAdapterMock> calypsoCard;

    /*
     * Successive calls to mockTransmitCardRequest() must be returned in call
     * order by cardReader->transmitCardRequest(), even though they may be
     * registered well before they are actually consumed (e.g. several
     * mockTransmitCardRequest() calls set up upfront for a sequence of
     * processCommands() calls). A fresh EXPECT_CALL per invocation would not
     * work: GMock resolves overlapping expectations on the same mock method
     * in reverse registration order, so only the last one registered would
     * ever be used.
     */
    std::deque<std::shared_ptr<CardResponseApi>> mQueuedCardResponses;
    bool mIsTransmitCardRequestMocked = false;

    void initCalypsoCardAndTransactionManager(
        const std::string& selectApplicationResponse);

    void initCalypsoCard(const std::string& selectApplicationResponse);

    virtual void initTransactionManager() = 0;

    std::shared_ptr<CardRequestSpi>
    mockTransmitCardRequest(std::vector<std::string>& apdus);

    /**
     * Pops and returns the next canned response queued by
     * mockTransmitCardRequest(). Exposed so that tests needing to verify call
     * order/content on cardReader->transmitCardRequest() (via a content
     * matcher) can still delegate to the same FIFO used by the default
     * WillRepeatedly() action.
     */
    std::shared_ptr<CardResponseApi> popNextQueuedCardResponse();

    class CardRequestMatcher
    //:
    // public ArgumentMatcher<CardRequestSpi>
    {
    public:
        std::vector<std::shared_ptr<ApduRequestSpi>> leftApduRequests;

        explicit CardRequestMatcher(
            const std::shared_ptr<CardRequestSpi>& cardRequest)
        : leftApduRequests(cardRequest->getApduRequests())
        {
        }

        bool
        matches(const std::shared_ptr<CardRequestSpi>& right)  // override
        {
            if (right == nullptr) {
                return false;
            }

            const std::vector<std::shared_ptr<ApduRequestSpi>> rightApduRequests
                = right->getApduRequests();
            if (leftApduRequests.size() != rightApduRequests.size()) {
                return false;
            }

            auto itLeft = leftApduRequests.begin();
            auto itRight = rightApduRequests.begin();

            while (itLeft != leftApduRequests.end()
                   && itRight != rightApduRequests.end()) {
                const std::vector<std::uint8_t>& leftApdu
                    = (*itLeft)->getApdu();
                const std::vector<std::uint8_t>& rightApdu
                    = (*itRight)->getApdu();
                if (!Arrays::equals(leftApdu, rightApdu)) {
                    return false;
                }

                ++itLeft;
                ++itRight;
            }

            return true;
        }
    };
};
