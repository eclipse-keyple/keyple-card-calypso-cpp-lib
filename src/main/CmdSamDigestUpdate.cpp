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

#include "CmdSamDigestUpdate.h"

/* Keyple Card Calypso */
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamDigestUpdate::mCommand = CalypsoSamCommand::DIGEST_UPDATE;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestUpdate::STATUS_TABLE = initStatusTable();

CmdSamDigestUpdate::CmdSamDigestUpdate(const CalypsoSam::ProductType productType,
                                       const bool encryptedSession,
                                       const std::vector<uint8_t>& digestData)
: AbstractSamCommand(mCommand)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x00;
    const uint8_t p2 = encryptedSession ? 0x80 : 0x00;

    if (digestData.empty() || digestData.size() > 255) {
        throw IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, digestData)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestUpdate::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect value in the incoming data: session " \
                                                 "in Rev.3.2 mode with encryption/decryption " \
                                                 "active and not enough data (less than 5 bytes " \
                                                 "for and odd occurrence or less than 2 bytes " \
                                                 "CalypsoSamIllegalParameterException for an even" \
                                                 " occurrence).",
                                                 typeid(CalypsoSamIncorrectInputDataException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("Incorrect P1 or P2.",
                                                 typeid(CalypsoSamIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamDigestUpdate::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
