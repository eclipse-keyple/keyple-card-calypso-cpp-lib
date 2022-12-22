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

#include "CmdSamDigestClose.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const CalypsoSamCommand CmdSamDigestClose::mCommand = CalypsoSamCommand::DIGEST_CLOSE;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestClose::STATUS_TABLE = initStatusTable();

CmdSamDigestClose::CmdSamDigestClose(const CalypsoSam::ProductType productType,
                                     const int expectedResponseLength)
: AbstractSamCommand(mCommand, expectedResponseLength)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(SamUtilAdapter::getClassByte(productType),
                            mCommand.getInstructionByte(),
                            0,
                            0,
                            expectedResponseLength)));
}

const std::vector<uint8_t> CmdSamDigestClose::getSignature() const
{
    return isSuccessful() ? getApduResponse()->getDataOut() : std::vector<uint8_t>();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestClose::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamDigestClose::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
