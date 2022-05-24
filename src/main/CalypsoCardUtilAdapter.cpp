/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CalypsoCardUtilAdapter.h"

/* Keyple Card Calypso */
#include "CalypsoCardCommand.h"
#include "CalypsoCardConstant.h"
#include "CardDataAccessException.h"
#include "CardPinException.h"
#include "CmdCardGetDataFci.h"
#include "CmdCardGetDataFcp.h"
#include "CmdCardSearchRecordMultiple.h"
#include "CmdCardSelectFile.h"
#include "DirectoryHeaderAdapter.h"

/* Keyple Core Util */
#include "Arrays.h"
#include "IllegalStateException.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

CalypsoCardUtilAdapter::CalypsoCardUtilAdapter() {}

void CalypsoCardUtilAdapter::updateCalypsoCard(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    const std::shared_ptr<AbstractCardCommand> command,
    const std::shared_ptr<ApduResponseApi> apduResponse,
    const bool isSessionOpen)
{
    if (command->getCommandRef() == CalypsoCardCommand::READ_RECORDS) {
        updateCalypsoCardReadRecords(calypsoCard,
                                     std::dynamic_pointer_cast<CmdCardReadRecords>(command),
                                     apduResponse,
                                     isSessionOpen);
    } else if (command->getCommandRef() == CalypsoCardCommand::GET_DATA) {
        if (std::dynamic_pointer_cast<CmdCardGetDataFci>(command)) {
            calypsoCard->initializeWithFci(apduResponse);
        } else if (std::dynamic_pointer_cast<CmdCardGetDataFcp>(command)) {
            updateCalypsoCardWithFcp(calypsoCard, command, apduResponse);
        } else if (std::dynamic_pointer_cast<CmdCardGetDataEfList>(command)) {
            updateCalypsoCardWithEfList(calypsoCard,
                                        std::dynamic_pointer_cast<CmdCardGetDataEfList>(command),
                                        apduResponse);
        } else if (std::dynamic_pointer_cast<CmdCardGetDataTraceabilityInformation>(command)) {
            updateCalypsoCardWithTraceabilityInformation(
                calypsoCard,
                std::dynamic_pointer_cast<CmdCardGetDataTraceabilityInformation>(command),
                apduResponse);
        } else {
            throw IllegalStateException("Unknown GET DATA command reference.");
        }
    } else if (command->getCommandRef() == CalypsoCardCommand::SEARCH_RECORD_MULTIPLE) {
        updateCalypsoCardSearchRecordMultiple(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardSearchRecordMultiple>(command),
            apduResponse,
            isSessionOpen);
    } else if (command->getCommandRef() == CalypsoCardCommand::READ_RECORD_MULTIPLE) {
        updateCalypsoCardReadRecordMultiple(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardReadRecordMultiple>(command),
            apduResponse,
            isSessionOpen);
    } else if (command->getCommandRef() == CalypsoCardCommand::SELECT_FILE) {
        updateCalypsoCardWithFcp(calypsoCard, command, apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::UPDATE_RECORD) {
        updateCalypsoCardUpdateRecord(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardUpdateRecord>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::WRITE_RECORD) {
        updateCalypsoCardWriteRecord(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardWriteRecord>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::APPEND_RECORD) {
        updateCalypsoCardAppendRecord(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardAppendRecord>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::INCREASE ||
               command->getCommandRef() == CalypsoCardCommand::DECREASE) {
        updateCalypsoCardIncreaseOrDecrease(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardIncreaseOrDecrease>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::INCREASE_MULTIPLE ||
               command->getCommandRef() == CalypsoCardCommand::DECREASE_MULTIPLE) {
        updateCalypsoCardIncreaseOrDecreaseMultiple(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardIncreaseOrDecreaseMultiple>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::OPEN_SESSION) {
        updateCalypsoCardOpenSession(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardOpenSession>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::CLOSE_SESSION) {
        updateCalypsoCardCloseSession(
            std::dynamic_pointer_cast<CmdCardCloseSession>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::READ_BINARY) {
        updateCalypsoCardReadBinary(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardReadBinary>(command),
            apduResponse,
            isSessionOpen);
    } else if (command->getCommandRef() == CalypsoCardCommand::UPDATE_BINARY) {
        updateCalypsoCardUpdateBinary(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardUpdateOrWriteBinary>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::WRITE_BINARY) {
        updateCalypsoCardWriteBinary(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardUpdateOrWriteBinary>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::GET_CHALLENGE) {
        updateCalypsoCardGetChallenge(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardGetChallenge>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::VERIFY_PIN) {
        updateCalypsoVerifyPin(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardVerifyPin>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::SV_GET) {
        updateCalypsoCardSvGet(
            calypsoCard,
            std::dynamic_pointer_cast<CmdCardSvGet>(command),
            apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::SV_RELOAD ||
               command->getCommandRef() == CalypsoCardCommand::SV_DEBIT ||
               command->getCommandRef() == CalypsoCardCommand::SV_UNDEBIT) {
        updateCalypsoCardSvOperation(calypsoCard, command, apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::INVALIDATE ||
               command->getCommandRef() == CalypsoCardCommand::REHABILITATE) {
        updateCalypsoInvalidateRehabilitate(command, apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::CHANGE_PIN) {
        updateCalypsoChangePin(std::dynamic_pointer_cast<CmdCardChangePin>(command), apduResponse);
    } else if (command->getCommandRef() == CalypsoCardCommand::CHANGE_KEY) {
        updateCalypsoChangeKey(std::dynamic_pointer_cast<CmdCardChangeKey>(command), apduResponse);
    } else {
        throw IllegalStateException("Unknown command reference.");
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCard(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    const std::vector<std::shared_ptr<AbstractCardCommand>>& commands,
    const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses,
    const bool isSessionOpen)
{
    auto responseIterator = apduResponses.begin();

    if (!commands.empty()) {
        for (const auto&  command : commands) {
            const std::shared_ptr<ApduResponseApi> apduResponse = *responseIterator++;
            updateCalypsoCard(calypsoCard, command, apduResponse, isSessionOpen);
        }
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardOpenSession(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardOpenSession> cmdCardOpenSession,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardOpenSession->setApduResponse(apduResponse);

    /* CL-CSS-INFORAT.1 */
    calypsoCard->setDfRatified(cmdCardOpenSession->wasRatified());

    const std::vector<uint8_t>& recordDataRead = cmdCardOpenSession->getRecordDataRead();

    if (recordDataRead.size() > 0) {
        calypsoCard->setContent(cmdCardOpenSession->getSfi(),
                                cmdCardOpenSession->getRecordNumber(),
                                recordDataRead);
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardCloseSession(
    std::shared_ptr<CmdCardCloseSession> cmdCardCloseSession,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardCloseSession->setApduResponse(apduResponse).checkStatus();
}

void CalypsoCardUtilAdapter::updateCalypsoCardReadRecords(
    const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    const std::shared_ptr<CmdCardReadRecords> cmdCardReadRecords,
    const std::shared_ptr<ApduResponseApi> apduResponse,
    const bool isSessionOpen)
{
    cmdCardReadRecords->setApduResponse(apduResponse);
    checkResponseStatusForStrictAndBestEffortMode(cmdCardReadRecords, isSessionOpen);

    /* Iterate over read records to fill the CalypsoCard */
    for (const auto& entry : cmdCardReadRecords->getRecords()) {
        calypsoCard->setContent(cmdCardReadRecords->getSfi(), entry.first, entry.second);
    }
}

void CalypsoCardUtilAdapter::checkResponseStatusForStrictAndBestEffortMode(
    const std::shared_ptr<AbstractCardCommand> command, const bool isSessionOpen)
{
    if (isSessionOpen) {
        command->checkStatus();
    } else {
        try {
            command->checkStatus();
        } catch (const CardDataAccessException& e) {
            /*
             * Best effort mode, do not throw exception for "file not found" and "record not found"
             * errors.
             */
            if (command->getApduResponse()->getStatusWord() != 0x6A82 &&
                command->getApduResponse()->getStatusWord() != 0x6A83) {
                throw e;
            }
        }
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardSearchRecordMultiple(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardSearchRecordMultiple> cmdCardSearchRecordMultiple,
    const std::shared_ptr<ApduResponseApi> apduResponse,
    const bool isSessionOpen)
{

    cmdCardSearchRecordMultiple->setApduResponse(apduResponse);
    checkResponseStatusForStrictAndBestEffortMode(cmdCardSearchRecordMultiple, isSessionOpen);

    if (cmdCardSearchRecordMultiple->getFirstMatchingRecordContent().size() > 0) {
        calypsoCard->setContent(
            cmdCardSearchRecordMultiple->getSearchCommandData()->getSfi(),
            cmdCardSearchRecordMultiple->getSearchCommandData()->getMatchingRecordNumbers()[0],
            cmdCardSearchRecordMultiple->getFirstMatchingRecordContent());
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardReadRecordMultiple(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardReadRecordMultiple> cmdCardReadRecordMultiple,
    const std::shared_ptr<ApduResponseApi> apduResponse,
    const bool isSessionOpen)
{
    cmdCardReadRecordMultiple->setApduResponse(apduResponse);
    checkResponseStatusForStrictAndBestEffortMode(cmdCardReadRecordMultiple, isSessionOpen);

    for (const auto& entry : cmdCardReadRecordMultiple->getResults()) {
        calypsoCard->setContent(cmdCardReadRecordMultiple->getSfi(),
                                entry.first,
                                entry.second,
                                cmdCardReadRecordMultiple->getOffset());
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardReadBinary(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardReadBinary> cmdCardReadBinary,
    const std::shared_ptr<ApduResponseApi> apduResponse,
    const bool isSessionOpen)
{

    cmdCardReadBinary->setApduResponse(apduResponse);
    checkResponseStatusForStrictAndBestEffortMode(cmdCardReadBinary, isSessionOpen);

    calypsoCard->setContent(cmdCardReadBinary->getSfi(),
                            1,
                            apduResponse->getDataOut(),
                            cmdCardReadBinary->getOffset());
}

void CalypsoCardUtilAdapter::updateCalypsoCardWithFcp(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<AbstractCardCommand> command,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{

    command->setApduResponse(apduResponse).checkStatus();

    std::vector<uint8_t> proprietaryInformation;
    if (command->getCommandRef() == CalypsoCardCommand::SELECT_FILE) {
        proprietaryInformation =
            std::dynamic_pointer_cast<CmdCardSelectFile>(command)->getProprietaryInformation();
    } else {
        proprietaryInformation =
            std::dynamic_pointer_cast<CmdCardGetDataFcp>(command)->getProprietaryInformation();
    }

    const uint8_t sfi = proprietaryInformation[CalypsoCardConstant::SEL_SFI_OFFSET];
    const uint8_t fileType = proprietaryInformation[CalypsoCardConstant::SEL_TYPE_OFFSET];

    if (fileType == CalypsoCardConstant::FILE_TYPE_MF ||
        fileType == CalypsoCardConstant::FILE_TYPE_MF ||
        fileType == CalypsoCardConstant::FILE_TYPE_DF) {
        const auto directoryHeader = createDirectoryHeader(proprietaryInformation);
        calypsoCard->setDirectoryHeader(directoryHeader);
    } else if (fileType == CalypsoCardConstant::FILE_TYPE_EF) {
        auto fileHeader = createFileHeader(proprietaryInformation);
        calypsoCard->setFileHeader(sfi, fileHeader);
    } else {
        throw IllegalStateException("Unknown file type: " + std::to_string(fileType));
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardWithEfList(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardGetDataEfList> command,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{

    command->setApduResponse(apduResponse).checkStatus();

    const std::map<const std::shared_ptr<FileHeaderAdapter>, const uint8_t> fileHeaderToSfiMap =
        command->getEfHeaders();

    for (const auto& entry : fileHeaderToSfiMap) {
        calypsoCard->setFileHeader(entry.second, entry.first);
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardWithTraceabilityInformation(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardGetDataTraceabilityInformation> command,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{

    command->setApduResponse(apduResponse).checkStatus();

    calypsoCard->setTraceabilityInformation(apduResponse->getDataOut());
}

void CalypsoCardUtilAdapter::updateCalypsoCardUpdateRecord(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardUpdateRecord> cmdCardUpdateRecord,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardUpdateRecord->setApduResponse(apduResponse).checkStatus();

    calypsoCard->setContent(cmdCardUpdateRecord->getSfi(),
                            cmdCardUpdateRecord->getRecordNumber(),
                            cmdCardUpdateRecord->getData());
}

void CalypsoCardUtilAdapter::updateCalypsoCardWriteRecord(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardWriteRecord> cmdCardWriteRecord,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{

    cmdCardWriteRecord->setApduResponse(apduResponse).checkStatus();

    calypsoCard->fillContent(cmdCardWriteRecord->getSfi(),
                             cmdCardWriteRecord->getRecordNumber(),
                             cmdCardWriteRecord->getData(),
                             0);
}

void CalypsoCardUtilAdapter::updateCalypsoCardUpdateBinary(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardUpdateOrWriteBinary> cmdCardUpdateBinary,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardUpdateBinary->setApduResponse(apduResponse).checkStatus();

    calypsoCard->setContent(cmdCardUpdateBinary->getSfi(),
                            1,
                            cmdCardUpdateBinary->getData(),
                            cmdCardUpdateBinary->getOffset());
}

void CalypsoCardUtilAdapter::updateCalypsoCardWriteBinary(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardUpdateOrWriteBinary> cmdCardWriteBinary,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardWriteBinary->setApduResponse(apduResponse).checkStatus();

    calypsoCard->fillContent(cmdCardWriteBinary->getSfi(),
                             1,
                             cmdCardWriteBinary->getData(),
                             cmdCardWriteBinary->getOffset());
}

void CalypsoCardUtilAdapter::updateCalypsoCardAppendRecord(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardAppendRecord> cmdCardAppendRecord,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardAppendRecord->setApduResponse(apduResponse).checkStatus();

    calypsoCard->addCyclicContent(cmdCardAppendRecord->getSfi(), cmdCardAppendRecord->getData());
}

void CalypsoCardUtilAdapter::updateCalypsoCardIncreaseOrDecrease(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardIncreaseOrDecrease> cmdCardIncreaseOrDecrease,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{

    cmdCardIncreaseOrDecrease->setApduResponse(apduResponse).checkStatus();

    calypsoCard->setCounter(cmdCardIncreaseOrDecrease->getSfi(),
                            cmdCardIncreaseOrDecrease->getCounterNumber(),
                            apduResponse->getDataOut());
}

void CalypsoCardUtilAdapter::updateCalypsoCardIncreaseOrDecreaseMultiple(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardIncreaseOrDecreaseMultiple> cmdCardIncreaseOrDecreaseMultiple,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{

    cmdCardIncreaseOrDecreaseMultiple->setApduResponse(apduResponse).checkStatus();

    for (const auto& entry : cmdCardIncreaseOrDecreaseMultiple->getNewCounterValues()) {
        calypsoCard->setCounter(cmdCardIncreaseOrDecreaseMultiple->getSfi(),
                                entry.first,
                                entry.second);
    }
}

void CalypsoCardUtilAdapter::updateCalypsoCardGetChallenge(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardGetChallenge> cmdCardGetChallenge,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardGetChallenge->setApduResponse(apduResponse).checkStatus();
    calypsoCard->setCardChallenge(cmdCardGetChallenge->getCardChallenge());
}

void CalypsoCardUtilAdapter::updateCalypsoVerifyPin(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardVerifyPin> cmdCardVerifyPin,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardVerifyPin->setApduResponse(apduResponse);
    calypsoCard->setPinAttemptRemaining(cmdCardVerifyPin->getRemainingAttemptCounter());

    try {
        cmdCardVerifyPin->checkStatus();
    } catch (const CardPinException& ex) {
        /*
         * Forward the exception if the operation do not target the reading of the attempt counter.
         * Catch it silently otherwise
         */
        if (!cmdCardVerifyPin->isReadCounterOnly()) {
            throw ex;
        }
    }
}

void CalypsoCardUtilAdapter::updateCalypsoChangePin(
    std::shared_ptr<CmdCardChangePin> cmdCardChangePin,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardChangePin->setApduResponse(apduResponse).checkStatus();
}

void CalypsoCardUtilAdapter::updateCalypsoChangeKey(
    std::shared_ptr<CmdCardChangeKey> cmdCardChangeKey,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardChangeKey->setApduResponse(apduResponse).checkStatus();
}

void CalypsoCardUtilAdapter::updateCalypsoCardSvGet(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<CmdCardSvGet> cmdCardSvGet,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardSvGet->setApduResponse(apduResponse).checkStatus();

    calypsoCard->setSvData(cmdCardSvGet->getCurrentKVC(),
                           cmdCardSvGet->getSvGetCommandHeader(),
                           cmdCardSvGet->getApduResponse()->getApdu(),
                           cmdCardSvGet->getBalance(),
                           cmdCardSvGet->getTransactionNumber(),
                           cmdCardSvGet->getLoadLog(),
                           cmdCardSvGet->getDebitLog());
}

void CalypsoCardUtilAdapter::updateCalypsoCardSvOperation(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard,
    std::shared_ptr<AbstractCardCommand> cmdCardSvOperation,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardSvOperation->setApduResponse(apduResponse).checkStatus();
    calypsoCard->setSvOperationSignature(cmdCardSvOperation->getApduResponse()->getDataOut());
}

void CalypsoCardUtilAdapter::updateCalypsoInvalidateRehabilitate(
    std::shared_ptr<AbstractCardCommand> cmdCardInvalidateRehabilitate,
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    cmdCardInvalidateRehabilitate->setApduResponse(apduResponse).checkStatus();
}

const std::shared_ptr<DirectoryHeader> CalypsoCardUtilAdapter::createDirectoryHeader(
    const std::vector<uint8_t>& proprietaryInformation)
{
    std::vector<uint8_t> accessConditions(CalypsoCardConstant::SEL_AC_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_AC_OFFSET,
                      accessConditions,
                      0,
                      CalypsoCardConstant::SEL_AC_LENGTH);

    std::vector<uint8_t> keyIndexes(CalypsoCardConstant::SEL_NKEY_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_NKEY_OFFSET,
                      keyIndexes,
                      0,
                      CalypsoCardConstant::SEL_NKEY_LENGTH);

    const uint8_t dfStatus = proprietaryInformation[CalypsoCardConstant::SEL_DF_STATUS_OFFSET];

    uint16_t lid = (((proprietaryInformation[CalypsoCardConstant::SEL_LID_OFFSET] << 8) & 0xff00) |
                     (proprietaryInformation[CalypsoCardConstant::SEL_LID_OFFSET + 1] & 0x00ff));

    return DirectoryHeaderAdapter::builder()
               ->lid(lid)
                .accessConditions(accessConditions)
                .keyIndexes(keyIndexes)
                .dfStatus(dfStatus)
                .kvc(WriteAccessLevel::PERSONALIZATION,
                     proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET])
                .kvc(WriteAccessLevel::LOAD,
                     proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET + 1])
                .kvc(WriteAccessLevel::DEBIT,
                     proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET + 2])
                .kif(WriteAccessLevel::PERSONALIZATION,
                     proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET])
                .kif(WriteAccessLevel::LOAD,
                     proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET + 1])
                .kif(WriteAccessLevel::DEBIT,
                     proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET + 2])
                .build();
}

ElementaryFile::Type CalypsoCardUtilAdapter::getEfTypeFromCardValue(const uint8_t efType)
{
    ElementaryFile::Type fileType;

    if (efType == CalypsoCardConstant::EF_TYPE_BINARY) {
        fileType = ElementaryFile::Type::BINARY;
    } else if (efType == CalypsoCardConstant::EF_TYPE_LINEAR) {
        fileType = ElementaryFile::Type::LINEAR;
    } else if (efType == CalypsoCardConstant::EF_TYPE_CYCLIC) {
        fileType = ElementaryFile::Type::CYCLIC;
    } else if (efType == CalypsoCardConstant::EF_TYPE_SIMULATED_COUNTERS) {
        fileType = ElementaryFile::Type::SIMULATED_COUNTERS;
    } else if (efType == CalypsoCardConstant::EF_TYPE_COUNTERS) {
        fileType = ElementaryFile::Type::COUNTERS;
    } else {
        throw IllegalStateException("Unknown EF Type: " + std::to_string(efType));
    }

    return fileType;
}

const std::shared_ptr<FileHeaderAdapter> CalypsoCardUtilAdapter::createFileHeader(
    const std::vector<uint8_t>& proprietaryInformation)
{
    const ElementaryFile::Type fileType =
        getEfTypeFromCardValue(proprietaryInformation[CalypsoCardConstant::SEL_EF_TYPE_OFFSET]);

    int recordSize;
    int recordsNumber;

    if (fileType == ElementaryFile::Type::BINARY) {
        recordSize =
            ((proprietaryInformation[CalypsoCardConstant::SEL_REC_SIZE_OFFSET] << 8) & 0x0000ff00) |
             (proprietaryInformation[CalypsoCardConstant::SEL_NUM_REC_OFFSET] & 0x000000ff);
        recordsNumber = 1;
    } else {
        recordSize = proprietaryInformation[CalypsoCardConstant::SEL_REC_SIZE_OFFSET];
        recordsNumber = proprietaryInformation[CalypsoCardConstant::SEL_NUM_REC_OFFSET];
    }

    std::vector<uint8_t> accessConditions(CalypsoCardConstant::SEL_AC_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_AC_OFFSET,
                      accessConditions,
                      0,
                      CalypsoCardConstant::SEL_AC_LENGTH);

    std::vector<uint8_t> keyIndexes(CalypsoCardConstant::SEL_NKEY_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_NKEY_OFFSET,
                      keyIndexes,
                      0,
                      CalypsoCardConstant::SEL_NKEY_LENGTH);

    const uint8_t dfStatus = proprietaryInformation[CalypsoCardConstant::SEL_DF_STATUS_OFFSET];

    const uint16_t sharedReference =
        ((proprietaryInformation[CalypsoCardConstant::SEL_DATA_REF_OFFSET] << 8) & 0xff00) |
        (proprietaryInformation[CalypsoCardConstant::SEL_DATA_REF_OFFSET + 1] & 0x00ff);

    const uint16_t lid =
             ((proprietaryInformation[CalypsoCardConstant::SEL_LID_OFFSET] << 8) & 0xff00) |
             (proprietaryInformation[CalypsoCardConstant::SEL_LID_OFFSET + 1] & 0x00ff);

    return FileHeaderAdapter::builder()->lid(lid)
                                        .recordsNumber(recordsNumber)
                                        .recordSize(recordSize)
                                        .type(fileType)
                                        .accessConditions(accessConditions)
                                        .keyIndexes(keyIndexes)
                                        .dfStatus(dfStatus)
                                        .sharedReference(sharedReference)
                                        .build();
}

}
}
}
