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

#include "keyple/card/calypso/CommandIncreaseOrDecrease.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardClass.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardDataOutOfBoundsException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSessionBufferOverflowException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalStateException;

const int CommandIncreaseOrDecrease::SW_POSTPONED_DATA = 0x6200;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandIncreaseOrDecrease::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6400,
              std::make_shared<Command::StatusProperties>(
                  "Too many modifications in session",
                  typeid(CardSessionBufferOverflowException))},
             {0x6700,
              std::make_shared<Command::StatusProperties>(
                  "Lc value not supported", typeid(CardDataAccessException))},
             {0x6981,
              std::make_shared<Command::StatusProperties>(
                  "The current EF is not a Counters or Simulated Counter EF",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (no session, wrong key, "
                  "encryption required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, DF is invalidated, "
                  "etc..)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Command not allowed (no current EF)",
                  typeid(CardDataAccessException))},
             {0x6A80,
              std::make_shared<Command::StatusProperties>(
                  "Overflow error", typeid(CardDataOutOfBoundsException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6103,
              std::make_shared<Command::StatusProperties>(
                  "Successful execution (possible only in ISO7816 T=0)",
                  typeid(CardIllegalParameterException))},
             {SW_POSTPONED_DATA,
              std::make_shared<Command::StatusProperties>(
                  "Successful execution, response data postponed until session "
                  "closing",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandIncreaseOrDecrease::CommandIncreaseOrDecrease(
    bool isDecreaseCommand,
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t sfi,
    int counterNumber,
    int incDecValue)
: Command(
      isDecreaseCommand ? CardCommandRef::DECREASE : CardCommandRef::INCREASE,
      std::unique_ptr<int>(new int(3)),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mCounterNumber(counterNumber)
, mIncDecValue(incDecValue)
{
    /*
     * Convert the integer value into a 3-byte buffer
     * CL-COUN-DATAIN.1
     */
    const std::vector<std::uint8_t> valueBuffer
        = ByteArrayUtil::extractBytes(incDecValue, 3);

    const std::uint8_t p2 = (sfi * 8);

    std::shared_ptr<DtoAdapters::ApduRequestAdapter> apduRequest;

    if (transactionContext->getCard()->getIsCounterValuePostponed() != nullptr
        && *(transactionContext->getCard()->getIsCounterValuePostponed())
               == false) {
        /*
         * For Rev 3 cards or legacy cards which not postpone data, this is a
         * case4 command; We set Le = 0.
         */
        apduRequest
            = std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                transactionContext->getCard()->getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                counterNumber,
                p2,
                valueBuffer,
                0));
    } else {
        /*
         * For legacy cards, this command is considered as case 3 (especially to
         * support postponed data); We set Le = null.
         */
        apduRequest
            = std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                transactionContext->getCard()->getCardClass().getValue(),
                getCommandRef().getInstructionByte(),
                counterNumber,
                p2,
                valueBuffer));

        apduRequest->addSuccessfulStatusWord(SW_POSTPONED_DATA);
    }

    setApduRequest(apduRequest);

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "Counter:" << counterNumber << ","
              << (isDecreaseCommand ? "Decrement" : "Increment") << ": "
              << incDecValue;

    addSubName(extraInfo.str());
}

void
CommandIncreaseOrDecrease::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandIncreaseOrDecrease::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandIncreaseOrDecrease::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()
        || getTransactionContext()->getCard()->getIsCounterValuePostponed()
               == nullptr) {
        return false;
    }

    updateTerminalSessionIfNeeded(buildAnticipatedResponse());

    return true;
}

void
CommandIncreaseOrDecrease::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    if (apduResponse->getDataOut().size() == 0
        && (getTransactionContext()->getCard()->getIsCounterValuePostponed()
                == nullptr
            || *(getTransactionContext()
                     ->getCard()
                     ->getIsCounterValuePostponed())
                   == true)) {
        setExpectedResponseLength(0);
    }

    Command::setApduResponseAndCheckStatus(apduResponse);

    if (apduResponse->getStatusWord() == SW_POSTPONED_DATA) {
        getTransactionContext()->getCard()->setIsCounterValuePostponed(true);
        getTransactionContext()->getCard()->setCounter(
            mSfi,
            mCounterNumber != 0 ? mCounterNumber : 1,
            buildAnticipatedDataOut());

    } else {
        getTransactionContext()->getCard()->setIsCounterValuePostponed(false);
        getTransactionContext()->getCard()->setCounter(
            mSfi,
            mCounterNumber != 0 ? mCounterNumber : 1,
            apduResponse->getDataOut());
    }

    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandIncreaseOrDecrease::getStatusTable() const
{
    return STATUS_TABLE;
}

std::vector<std::uint8_t>
CommandIncreaseOrDecrease::buildAnticipatedResponse()
{
    std::vector<std::uint8_t> response;
    if (getTransactionContext()->getCard()->getIsCounterValuePostponed()
            != nullptr
        && *(getTransactionContext()->getCard()->getIsCounterValuePostponed())
               == true) {
        /* Response = 6200 */
        response.resize(2);
        response[0] = 0x62; /* SW 6200 */
        response[1] = 0x00;
    } else {
        /* Response = NNNNNN9000 */
        const std::vector<std::uint8_t> dataOut = buildAnticipatedDataOut();
        response.resize(5);
        response[0] = dataOut[0];
        response[1] = dataOut[1];
        response[2] = dataOut[2];
        response[3] = 0x90; /* SW 9000 */
        response[4] = 0x00;
    }

    return response;
}

std::vector<std::uint8_t>
CommandIncreaseOrDecrease::buildAnticipatedDataOut()
{
    const std::shared_ptr<ElementaryFile> ef
        = getTransactionContext()->getCard()->getFileBySfi(mSfi);

    if (ef != nullptr) {
        std::shared_ptr<int> oldCounterValue
            = ef->getData()->getContentAsCounterValue(
                mCounterNumber != 0 ? mCounterNumber : 1);
        if (oldCounterValue != nullptr) {
            return ByteArrayUtil::extractBytes(
                getCommandRef() == CardCommandRef::DECREASE
                    ? *oldCounterValue - mIncDecValue
                    : *oldCounterValue + mIncDecValue,
                3);
        }
    }

    throw IllegalStateException(
        std::string("Unable to determine anticipated APDU response ")
        + "because the counter has not been read beforehand. "
        + "Command: " + getName() + ", SFI: " + HexUtil::toHex(mSfi)
        + "h, Counter: " + std::to_string(mCounterNumber));
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
