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

#include "CmdSamCardGenerateKey.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamCardGenerateKey::mCommand = CalypsoSamCommand::CARD_GENERATE_KEY;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamCardGenerateKey::STATUS_TABLE = initStatusTable();

CmdSamCardGenerateKey::CmdSamCardGenerateKey(const CalypsoSam::ProductType productType,
                                             const uint8_t cipheringKif,
                                             const uint8_t cipheringKvc,
                                             const uint8_t sourceKif,
                                             const uint8_t sourceKvc)
: AbstractSamCommand(mCommand)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);

    uint8_t p1;
    uint8_t p2;
    std::vector<uint8_t> data;

    if (cipheringKif == 0 && cipheringKvc == 0) {
        /* Case where the source key is ciphered by the null key */
        p1 = 0xFF;
        p2 = 0x00;

        data = std::vector<uint8_t>(3);
        data[0] = sourceKif;
        data[1] = sourceKvc;
        data[2] = 0x90;
    } else {
        p1 = 0xFF;
        p2 = 0xFF;

        data = std::vector<uint8_t>(5);
        data[0] = cipheringKif;
        data[1] = cipheringKvc;
        data[2] = sourceKif;
        data[3] = sourceKvc;
        data[4] = 0x90;
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, data)));
}

const std::vector<uint8_t> CmdSamCardGenerateKey::getCipheredData() const
{
    return isSuccessful() ? getApduResponse()->getDataOut() : std::vector<uint8_t>();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamCardGenerateKey::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("Incorrect P1 or P2",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect incoming data: unknown or incorrect " \
                                                 "format",
                                                 typeid(CalypsoSamIncorrectInputDataException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: ciphering key or key to " \
                                                 "cipher not found",
                                                 typeid(CalypsoSamDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamCardGenerateKey::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
