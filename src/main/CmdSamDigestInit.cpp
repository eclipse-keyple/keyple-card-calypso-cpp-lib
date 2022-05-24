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

#include "CmdSamDigestInit.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamDigestInit::mCommand = CalypsoSamCommand::DIGEST_INIT;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestInit::STATUS_TABLE = initStatusTable();

CmdSamDigestInit::CmdSamDigestInit(
  const CalypsoSam::ProductType productType,
  const bool verificationMode,
  const bool confidentialSessionMode,
  const uint8_t workKif,
  const uint8_t workKvc,
  const std::vector<uint8_t>& digestData)
: AbstractSamCommand(mCommand)
{
    if (workKif == 0x00 || workKvc == 0x00) {
        throw IllegalArgumentException("Bad kif or kvc!");
    }

    if (digestData.empty()) {
        throw IllegalArgumentException("Digest data is null!");
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    uint8_t p1 = 0x00;

    if (verificationMode) {
        p1 += 1;
    }

    if (confidentialSessionMode) {
        p1 += 2;
    }

    const uint8_t p2 = 0xFF;

    std::vector<uint8_t> dataIn(2 + digestData.size());
    dataIn[0] = workKif;
    dataIn[1] = workKvc;
    System::arraycopy(digestData, 0, dataIn, 2, digestData.size());

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, dataIn)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestInit::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("Incorrect P2.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: signing key not found.",
                                                 typeid(CalypsoSamDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamDigestInit::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
