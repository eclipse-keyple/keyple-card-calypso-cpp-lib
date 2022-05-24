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

#include "CmdCardInvalidate.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"

/* Keyple Core Util */
#include "ApduUtil.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const CalypsoCardCommand CmdCardInvalidate::mCommand = CalypsoCardCommand::INVALIDATE;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardInvalidate::STATUS_TABLE = initStatusTable();

CmdCardInvalidate::CmdCardInvalidate(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand)
{
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(), mCommand.getInstructionByte(), p1, p2)));
}

bool CmdCardInvalidate::isSessionBufferUsed() const
{
    return true;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardInvalidate::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session.",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (no session, " \
                                                 "wrong key).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (DF context is invalid).",
                                                 typeid(CardAccessForbiddenException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardInvalidate::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
