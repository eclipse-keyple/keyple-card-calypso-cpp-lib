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

#include "CmdCardSelectFile.h"

/* Keyple Card Calypso */
#include "CardIllegalParameterException.h"
#include "CardDataAccessException.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "BerTlvUtil.h"
#include "ByteArrayUtil.h"
#include "IllegalStateException.h"
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const int CmdCardSelectFile::TAG_PROPRIETARY_INFORMATION = 0x85;
const CalypsoCardCommand CmdCardSelectFile::mCommand = CalypsoCardCommand::SELECT_FILE;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSelectFile::STATUS_TABLE = initStatusTable();

CmdCardSelectFile::CmdCardSelectFile(const CalypsoCardClass calypsoCardClass,
                                     const SelectFileControl selectFileControl)
: AbstractCardCommand(mCommand)
{
    const uint8_t cla = calypsoCardClass.getValue();
    uint8_t p1;
    uint8_t p2;
    const std::vector<uint8_t> selectData = {0x00, 0x00};

    switch (selectFileControl) {
    case SelectFileControl::FIRST_EF:
        p1 = 0x02;
        p2 = 0x00;
        break;
    case SelectFileControl::NEXT_EF:
        p1 = 0x02;
        p2 = 0x02;
        break;
    case SelectFileControl::CURRENT_DF:
        /* CL-KEY-KIFSF.1 */
        p1 = 0x09;
        p2 = 0x00;
        break;
    default:
        throw IllegalStateException("Unsupported selectFileControl parameter " \
                                    "FIXME: selectFileControl.name()");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, selectData, 0x00)));


    addSubName("SELECTIONCONTROL FIXME: selectFileControl");
}

CmdCardSelectFile::CmdCardSelectFile(const CalypsoCardClass calypsoCardClass,
                                     const CalypsoCard::ProductType productType,
                                     const uint16_t lid)
: AbstractCardCommand(mCommand)
{
    /*
     * handle the REV1 case
     * CL-KEY-KIFSF.1
     * If legacy and rev2 then 02h else if legacy then 08h else 09h
     */
    uint8_t p1;

    if (calypsoCardClass == CalypsoCardClass::LEGACY &&
         productType == CalypsoCard::ProductType::PRIME_REVISION_2) {
        p1 = 0x02;
    } else if (calypsoCardClass == CalypsoCardClass::LEGACY) {
        p1 = 0x08;
    } else {
        p1 = 0x09;
    }

    const std::vector<uint8_t> dataIn = {static_cast<uint8_t>((lid >> 8) & 0xFF),
                                         static_cast<uint8_t>(lid & 0xFF)};

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            p1,
                            0x00,
                            dataIn,
                            0x00)));

    addSubName("LID=" + ByteArrayUtil::toHex(dataIn));
}

bool CmdCardSelectFile::isSessionBufferUsed() const
{
    return false;
}

const std::vector<uint8_t>& CmdCardSelectFile::getProprietaryInformation()
{
    if (mProprietaryInformation.empty()) {
        const std::map<const int, const std::vector<uint8_t>> tags =
            BerTlvUtil::parseSimple(getApduResponse()->getDataOut(), true);

        const auto it = tags.find(TAG_PROPRIETARY_INFORMATION);
        if (it == tags.end()) {
            throw new IllegalStateException("Proprietary information: tag not found.");
        }

        mProprietaryInformation = it->second;
        Assert::getInstance().isEqual(mProprietaryInformation.size(), 23, "proprietaryInformation");
    }

    return mProprietaryInformation;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSelectFile::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6119,
              std::make_shared<StatusProperties>("Correct execution (ISO7816 T=0).",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardSelectFile::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
