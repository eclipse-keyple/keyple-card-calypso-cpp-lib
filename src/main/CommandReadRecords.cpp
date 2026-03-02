/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/CommandReadRecords.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardClass.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandReadRecords::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6981,
              std::make_shared<Command::StatusProperties>(
                  "Command forbidden on binary files",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (PIN code not presented, "
                  "encryption required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, stored value log file "
                  "and a stored value "
                  "operation was done during the current session)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Command not allowed (no current EF)",
                  typeid(CardDataAccessException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<Command::StatusProperties>(
                  "Record not found (record index is 0, or above NumRec",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P2 value not supported",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandReadRecords::CommandReadRecords(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    int sfi,
    int firstRecordNumber,
    ReadMode readMode,
    std::unique_ptr<int> expectedLength,
    int recordSize)
: Command(
      CardCommandRef::READ_RECORDS,
      std::move(expectedLength),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mFirstRecordNumber(firstRecordNumber)
, mRecordSize(recordSize)
, mReadMode(readMode)
, mIsPreOpenMode(
      transactionContext->getCard() != nullptr
      && transactionContext->getCard()->getPreOpenWriteAccessLevel()
             != WriteAccessLevel::UNKOWN)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();

    const std::uint8_t p1 = firstRecordNumber;
    std::uint8_t p2 = (sfi == 0x00) ? 0x05 : ((sfi * 8) + 5);
    if (readMode == ReadMode::ONE_RECORD) {
        p2 -= 1;
    }
    /*
     * Careful, 'expectedLength' is already std::move()'d into the Command base
     * class subobject above, so it is unconditionally null here. Read the
     * value back through the base class accessor instead.
     */
    const int* expectedResponseLength = getExpectedResponseLength();
    const std::uint8_t le
        = expectedResponseLength != nullptr ? *expectedResponseLength : 0x00;

    /* APDU Case 2 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass, getCommandRef().getInstructionByte(), p1, p2, le)));

    const std::string subName
        = std::string("SFI: ") + HexUtil::toHex(static_cast<std::uint32_t>(sfi))
          + "h, Rec: " + std::to_string(firstRecordNumber) + ", Read mode: "
          + (readMode == CommandReadRecords::ReadMode::ONE_RECORD
                 ? "ONE_RECORD"
                 : "MULTIPLE_RECORD")
          + ", Expected length: "
          + (expectedResponseLength != nullptr
                 ? std::to_string(*expectedResponseLength)
                 : "null");
    addSubName(subName);
}

void
CommandReadRecords::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandReadRecords::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandReadRecords::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (!getCommandContext()->isSecureSessionOpen()) {
        return true; /* Nothing to synchronize */
    }

    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    if (!mIsPreOpenMode) {
        return false;
    }

    /* Pre-open mode without encryption in secure session */
    if (!isCryptoServiceSynchronized()) {
        const std::vector<std::uint8_t> anticipatedApduResponse(
            buildAnticipatedResponse());
        if (anticipatedApduResponse.empty()) {
            const std::string sfiHex
                = HexUtil::toHex(static_cast<std::uint32_t>(mSfi));
            mLogger->warn(
                std::string("Unable to determine anticipated APDU response ")
                    + "because the record or some records have not been read "
                    + "beforehand [command=%, sfi=%, record=%]\n",
                getName(),
                sfiHex,
                mFirstRecordNumber);

            return false;
        }

        mAnticipatedDataOut = Arrays::copyOf(
            anticipatedApduResponse, anticipatedApduResponse.size() - 2);

        updateTerminalSessionIfNeeded(anticipatedApduResponse);
    }

    return true;
}

void
CommandReadRecords::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    if (!setApduResponseAndCheckStatusInBestEffortMode(apduResponse)) {
        return;
    }

    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
    if (mReadMode == CommandReadRecords::ReadMode::ONE_RECORD) {
        getTransactionContext()->getCard()->setContent(
            mSfi, mFirstRecordNumber, dataOut);
    } else {
        int apduLen = dataOut.size();
        int index = 0;
        while (apduLen > 0) {
            const std::uint8_t recordNb = dataOut[index++];
            const std::uint8_t len = dataOut[index++];
            getTransactionContext()->getCard()->setContent(
                mSfi,
                recordNb,
                Arrays::copyOfRange(dataOut, index, index + len));
            index += len;
            apduLen -= (2 + len);
        }
    }
    if (!isCryptoServiceSynchronized()) {
        updateTerminalSessionIfNeeded();
    } else if (
        getCommandContext()->isSecureSessionOpen() && mIsPreOpenMode
        && !Arrays::equals(dataOut, mAnticipatedDataOut)) {
        throw CardSecurityContextException(
            "Data out does not match the anticipated data out",
            CardCommandRef::READ_RECORDS);
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandReadRecords::getStatusTable() const
{
    return STATUS_TABLE;
}

std::vector<std::uint8_t>
CommandReadRecords::buildAnticipatedResponse()
{
    std::shared_ptr<ElementaryFile> ef
        = getTransactionContext()->getCard()->getFileBySfi(mSfi);
    if (ef == nullptr) {
        return {};
    }

    return mReadMode == CommandReadRecords::ReadMode::ONE_RECORD
               ? buildAnticipatedResponseForOneRecordMode(ef)
               : buildAnticipatedResponseForMultipleRecordsMode(ef);
}

std::vector<std::uint8_t>
CommandReadRecords::buildAnticipatedResponseForOneRecordMode(
    const std::shared_ptr<ElementaryFile>& ef)
{
    const std::vector<std::uint8_t> content
        = ef->getData()->getContent(mFirstRecordNumber);

    const int expectedResponseLength = *getExpectedResponseLength();
    if (content.size() > 0
        && static_cast<int>(content.size()) >= expectedResponseLength) {
        const int length = expectedResponseLength != 0 ? expectedResponseLength
                                                       : content.size();
        std::vector<std::uint8_t> apdu(length + 2);
        /* Record content */
        System::arraycopy(content, 0, apdu, 0, length);
        /* SW 9000 */
        apdu[length] = 0x90;

        return apdu;
    }

    return {};
}

std::vector<std::uint8_t>
CommandReadRecords::buildAnticipatedResponseForMultipleRecordsMode(
    const std::shared_ptr<ElementaryFile>& ef)
{
    std::vector<std::uint8_t> apdu(*getExpectedResponseLength() + 2);
    const int nbRecords = *getExpectedResponseLength() / (mRecordSize + 2);
    const int lastRecordNumber = mFirstRecordNumber + nbRecords - 1;
    int index = 0;

    for (int i = mFirstRecordNumber; i <= lastRecordNumber; i++) {
        const std::vector<std::uint8_t> content = ef->getData()->getContent(i);
        if (static_cast<int>(content.size()) >= mRecordSize) {
            /* Record number */
            apdu[index++] = i;
            /* Record size */
            apdu[index++] = mRecordSize;
            /* Record content */
            System::arraycopy(content, 0, apdu, index, mRecordSize);
            index += mRecordSize;
        } else {
            return {};
        }
    }

    /* SW 9000 */
    apdu[index] = 0x90;

    return apdu;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
