/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
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

CmdCardGetDataFcp::CmdCardGetDataFcp(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            0x00,
                            0x62,
                            0x00)));
}

bool CmdCardGetDataFcp::isSessionBufferUsed() const
{
    return false;
}

const std::vector<uint8_t>& CmdCardGetDataFcp::getProprietaryInformation()
{
    if (mProprietaryInformation.empty()) {
        const std::map<const int, const std::vector<uint8_t>> tags =
            BerTlvUtil::parseSimple(getApduResponse()->getDataOut(), true);

        const auto it = tags.find(TAG_PROPRIETARY_INFORMATION);
        if (it == tags.end()) {
            throw IllegalStateException("Proprietary information: tag not found.");
        }

        mProprietaryInformation = it->second;
        Assert::getInstance().isEqual(mProprietaryInformation.size(), 23, "proprietaryInformation");
    }

    return mProprietaryInformation;
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
