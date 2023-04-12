
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

#include "CmdCardIncreaseOrDecreaseMultiple.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardIncreaseOrDecreaseMultiple::STATUS_TABLE = initStatusTable();

CmdCardIncreaseOrDecreaseMultiple::CmdCardIncreaseOrDecreaseMultiple(
  const bool isDecreaseCommand,
  const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
  const uint8_t sfi,
  const std::map<const int, const int> counterNumberToIncDecValueMap)
: AbstractCardCommand(isDecreaseCommand ? CalypsoCardCommand::DECREASE_MULTIPLE :
                                          CalypsoCardCommand::INCREASE_MULTIPLE,
                      0,
                      calypsoCard),
  mSfi(sfi),
  mCounterNumberToIncDecValueMap(counterNumberToIncDecValueMap)
{
    const uint8_t p1 = 0;
    const uint8_t p2 = sfi * 8;
    std::vector<uint8_t> dataIn(4 * counterNumberToIncDecValueMap.size());
    int index = 0;

    for (const auto& entry : counterNumberToIncDecValueMap) {

        dataIn[index] = static_cast<uint8_t>(entry.first);
        const int incDecValue = entry.second;
        ByteArrayUtil::copyBytes(incDecValue, dataIn, index + 1, 3);
        index += 4;
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCard->getCardClass().getValue(),
                            getCommandRef().getInstructionByte(),
                            p1,
                            p2,
                            dataIn,
                            0)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h";

    for (const auto& entry : counterNumberToIncDecValueMap) {

        extraInfo << ", " << entry.first << ":" << entry.second;
    }

    addSubName(extraInfo.str());
}

bool CmdCardIncreaseOrDecreaseMultiple::isSessionBufferUsed() const
{
    return true;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardIncreaseOrDecreaseMultiple::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session.",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("Incorrect EF type: not a Counters EF.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (no secure " \
                                                 "session, incorrect key, encryption required, " \
                                                 "PKI mode and not Always access mode).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, DF is " \
                                                 "invalid, etc.).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Incorrect file type: the Current File is not " \
                                                 "an EF. Supersedes 6981h.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect command data (Overflow error, " \
                                                 "Incorrect counter number, Counter number " \
                                                 "present more than once).",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardIncreaseOrDecreaseMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

void CmdCardIncreaseOrDecreaseMultiple::parseApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    if (apduResponse->getDataOut().size() > 0) {

        const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
        const int nbCounters = static_cast<int>(dataOut.size() / 4);

        for (int i = 0; i < nbCounters; i++) {

            getCalypsoCard()->setCounter(mSfi,
                                         dataOut[i * 4] & 0xFF,
                                         Arrays::copyOfRange(dataOut, (i * 4) + 1, (i * 4) + 4));
        }
    }
}

uint8_t CmdCardIncreaseOrDecreaseMultiple::getSfi() const
{
    return mSfi;
}

const std::map<const int, const int>&
    CmdCardIncreaseOrDecreaseMultiple::getCounterNumberToIncDecValueMap() const
{
    return mCounterNumberToIncDecValueMap;
}

}
}
}
