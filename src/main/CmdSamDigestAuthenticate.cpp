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

#include "CmdSamDigestAuthenticate.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamSecurityDataException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamDigestAuthenticate::mCommand = CalypsoSamCommand::DIGEST_AUTHENTICATE;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestAuthenticate::STATUS_TABLE = initStatusTable();

CmdSamDigestAuthenticate::CmdSamDigestAuthenticate(const CalypsoSam::ProductType productType,
                                                   const std::vector<uint8_t>& signature)
: AbstractSamCommand(mCommand)
{
    if (signature.empty()) {
        throw IllegalArgumentException("Signature can't be null");
    }

    if (signature.size() != 4 && signature.size() != 8 && signature.size() != 16) {
        throw IllegalArgumentException("Signature is not the right length : length is " +
                                       std::to_string(signature.size()));
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, signature)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestAuthenticate::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6988,
              std::make_shared<StatusProperties>("Incorrect signature.",
                                                 typeid(CalypsoSamSecurityDataException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamDigestAuthenticate::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
