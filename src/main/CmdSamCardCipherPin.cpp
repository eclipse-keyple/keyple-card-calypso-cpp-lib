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

#include "CmdSamCardCipherPin.h"

/* Keyple Card Calypso */
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamAccessForbiddenException.h"
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

const CalypsoSamCommand CmdSamCardCipherPin::mCommand = CalypsoSamCommand::CARD_CIPHER_PIN;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamCardCipherPin::STATUS_TABLE = initStatusTable();

CmdSamCardCipherPin::CmdSamCardCipherPin(const CalypsoSam::ProductType productType,
                                         const uint8_t cipheringKif,
                                         const uint8_t cipheringKvc,
                                         const std::vector<uint8_t>& currentPin,
                                         const std::vector<uint8_t>& newPin)
: AbstractSamCommand(mCommand)
{
    if (currentPin.size() != 4) {
        throw IllegalArgumentException("Bad current PIN value.");
    }

    if (!newPin.empty() && newPin.size() != 4) {
        throw IllegalArgumentException("Bad new PIN value.");
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);

    uint8_t p1;
    uint8_t p2;
    std::vector<uint8_t> data;

    if (newPin.empty()) {
        /* No new PIN is provided, we consider it's a PIN verification */
        p1 = 0x80;
        data = std::vector<uint8_t>(6);
    } else {
        /* A new PIN is provided, we consider it's a PIN update */
        p1 = 0x40;
        data = std::vector<uint8_t>(10);
        System::arraycopy(newPin, 0, data, 6, 4);
    }
    p2 = 0xFF; /* KIF and KVC in incoming data */

    data[0] = cipheringKif;
    data[1] = cipheringKvc;

    System::arraycopy(currentPin, 0, data, 2, 4);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, data)));
}

const std::vector<uint8_t> CmdSamCardCipherPin::getCipheredData() const
{
    return getApduResponse()->getDataOut();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamCardCipherPin::initStatusTable()
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
              std::make_shared<StatusProperties>("Incorrect P1 or P2",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: ciphering key not found",
                                                 typeid(CalypsoSamDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamCardCipherPin::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
