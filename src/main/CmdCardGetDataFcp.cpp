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

#include "CmdCardGetDataFcp.h"

/* Keyple Card Calypso */
#include "CmdCardSelectFile.h"
#include "CardDataAccessException.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "BerTlvUtil.h"
#include "IllegalStateException.h"
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoCardCommand CmdCardGetDataFcp::mCommand = CalypsoCardCommand::GET_DATA;
const int CmdCardGetDataFcp::TAG_PROPRIETARY_INFORMATION = 0x85;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataFcp::STATUS_TABLE = initStatusTable();

CmdCardGetDataFcp::CmdCardGetDataFcp(const std::shared_ptr<CalypsoCardAdapter> calypsoCard)
: AbstractCardCommand(mCommand, 0, calypsoCard)
{
    buildCommand(calypsoCard->getCardClass());
}

CmdCardGetDataFcp::CmdCardGetDataFcp(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand, 0, nullptr)
{
    buildCommand(calypsoCardClass);
}

void CmdCardGetDataFcp::buildCommand(const CalypsoCardClass calypsoCardClass)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            0x00,
                            0x62,
                            0x00)));
}

void CmdCardGetDataFcp::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    CmdCardSelectFile::parseProprietaryInformation(apduResponse->getDataOut(), getCalypsoCard());
}

bool CmdCardGetDataFcp::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataFcp::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6A88,
              std::make_shared<StatusProperties>("Data object not found (optional mode not " \
                                                 "available).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardGetDataFcp::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
