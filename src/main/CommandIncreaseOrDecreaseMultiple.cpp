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

#include "keyple/card/calypso/CommandIncreaseOrDecreaseMultiple.hpp"

#include <map>
#include <memory>
#include <sstream>
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
#include "keyple/core/util/cpp/MapUtils.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::MapUtils;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalStateException;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandIncreaseOrDecreaseMultiple::STATUS_TABLE = [] {
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
                  "Security conditions not fulfilled (no secure session, "
                  "incorrect key, encryption required, PKI mode and not Always "
                  "access mode)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, DF is invalidated, "
                  "etc.)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect file type: the Current File is not an EF. "
                  "Supersedes 6981h",
                  typeid(CardDataAccessException))},
             {0x6A80,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect command data (Overflow error, Incorrect counter "
                  "number, Counter number present more than once)",
                  typeid(CardIllegalParameterException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandIncreaseOrDecreaseMultiple::CommandIncreaseOrDecreaseMultiple(
    bool isDecreaseCommand,
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t sfi,
    const std::map<int, int>& counterNumberToIncDecValueMap)
: Command(
      isDecreaseCommand ? CardCommandRef::DECREASE_MULTIPLE
                        : CardCommandRef::INCREASE_MULTIPLE,
      std::unique_ptr<int>(new int(counterNumberToIncDecValueMap.size() * 4)),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mCounterNumberToIncDecValueMap(counterNumberToIncDecValueMap)
{
    const std::uint8_t p1 = 0;
    const std::uint8_t p2 = (sfi * 8);
    std::vector<std::uint8_t> dataIn(4 * counterNumberToIncDecValueMap.size());
    int index = 0;

    for (const auto& entry : counterNumberToIncDecValueMap) {
        dataIn[index] = static_cast<std::uint8_t>(entry.first);
        int incDecValue = entry.second;
        ByteArrayUtil::copyBytes(incDecValue, dataIn, index + 1, 3);
        index += 4;
    }

    /* APDU Case 4 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            transactionContext->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            p1,
            p2,
            dataIn,
            0x00)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << HexUtil::toHex(sfi);
    for (const auto& entry : counterNumberToIncDecValueMap) {
        extraInfo << ", ";
        extraInfo << entry.first << ": " << entry.second;
    }

    addSubName(extraInfo.str());
}

void
CommandIncreaseOrDecreaseMultiple::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandIncreaseOrDecreaseMultiple::isCryptoServiceRequiredToFinalizeRequest()
    const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandIncreaseOrDecreaseMultiple ::
    synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    updateTerminalSessionIfNeeded(APDU_RESPONSE_9000);

    return true;
}

void
CommandIncreaseOrDecreaseMultiple::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);

    if (apduResponse->getDataOut().size() > 0) {
        const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
        int nbCounters = dataOut.size() / 4;
        for (int i = 0; i < nbCounters; i++) {
            getTransactionContext()->getCard()->setCounter(
                mSfi,
                dataOut[i * 4] & 0xFF,
                Arrays::copyOfRange(dataOut, (i * 4) + 1, (i * 4) + 4));
        }
    }

    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandIncreaseOrDecreaseMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

std::vector<std::uint8_t>
CommandIncreaseOrDecreaseMultiple::buildAnticipatedResponse()
{
    /* Response = CCVVVVVV..CCVVVVVV9000 */
    std::map<const int, const int> oldCounterValues = getOldCounterValues();
    std::vector<std::uint8_t> response(
        2 + (mCounterNumberToIncDecValueMap.size() * 4));
    int index = 0;

    for (const auto& entry : mCounterNumberToIncDecValueMap) {
        response[index] = static_cast<std::uint8_t>(entry.first);
        int newCounterValue;

        if (getCommandRef() == CardCommandRef::DECREASE_MULTIPLE) {
            newCounterValue = oldCounterValues[entry.first] - entry.second;
        } else {
            newCounterValue = oldCounterValues[entry.first] + entry.second;
        }

        ByteArrayUtil::copyBytes(newCounterValue, response, index + 1, 3);
        index += 4;
    }

    /* SW 9000 */
    response[index] = 0x90;
    response[index + 1] = 0x00;

    return response;
}

std::map<const int, const int>
CommandIncreaseOrDecreaseMultiple::getOldCounterValues()
{
    std::shared_ptr<ElementaryFile> ef
        = getTransactionContext()->getCard()->getFileBySfi(mSfi);

    if (ef != nullptr) {
        const std::map<const int, const int> allCountersValue
            = ef->getData()->getAllCountersValue();

        const std::vector<int> allCountersValueKeySet
            = MapUtils::getKeySet(allCountersValue);
        const std::vector<int> counterNumberToIncDecValueKeySet
            = MapUtils::getKeySet(mCounterNumberToIncDecValueMap);

        if (Arrays::containsAll(
                allCountersValueKeySet, counterNumberToIncDecValueKeySet)) {
            return allCountersValue;
        }
    }

    throw new IllegalStateException(
        std::string("Unable to determine anticipated APDU response ")
        + "because some expected counters have not been read beforehand. "
        + "Command: " + getName() + ", SFI: " + HexUtil::toHex(mSfi) + "h");
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
