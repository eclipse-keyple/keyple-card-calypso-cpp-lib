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

#include "CmdCardSelectFile.h"

/* Keyple Card Calypso */
#include "CalypsoCardConstant.h"
#include "CardIllegalParameterException.h"
#include "CardDataAccessException.h"
#include "DirectoryHeaderAdapter.h"
#include "FileHeaderAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "BerTlvUtil.h"
#include "ByteArrayUtil.h"
#include "HexUtil.h"
#include "IllegalStateException.h"
#include "KeypleAssert.h"
#include "StringUtils.h"
#include "System.h"

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

CmdCardSelectFile::CmdCardSelectFile(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                                     const SelectFileControl selectFileControl)
: AbstractCardCommand(mCommand, 0, calypsoCard)
{
    buildCommand(calypsoCard->getCardClass(), selectFileControl);
}

CmdCardSelectFile::CmdCardSelectFile(const CalypsoCardClass calypsoCardClass,
                                     const SelectFileControl selectFileControl)
: AbstractCardCommand(mCommand, 0, nullptr)
{
    buildCommand(calypsoCardClass, selectFileControl);
}

CmdCardSelectFile::CmdCardSelectFile(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                                     const uint16_t lid)
: AbstractCardCommand(mCommand, 0, calypsoCard)
{
    buildCommand(calypsoCard->getCardClass(), calypsoCard->getProductType(), lid);
}

CmdCardSelectFile::CmdCardSelectFile(const CalypsoCardClass calypsoCardClass,
                                     const CalypsoCard::ProductType productType,
                                     const uint16_t lid)
: AbstractCardCommand(mCommand, 0, nullptr)
{
    buildCommand(calypsoCardClass, productType, lid);
}

void CmdCardSelectFile::buildCommand(const CalypsoCardClass calypsoCardClass,
                                     const SelectFileControl selectFileControl)
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

void CmdCardSelectFile::buildCommand(const CalypsoCardClass calypsoCardClass,
                                     const CalypsoCard::ProductType productType,
                                     const uint16_t lid)
{
    /*
        * Handle the REV1 case
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

    const std::vector<uint8_t> dataIn = ByteArrayUtil::extractBytes(lid, 2);

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            p1,
                            0x00,
                            dataIn,
                            0x00)));

    addSubName("LID=" + HexUtil::toHex(dataIn));
}

void CmdCardSelectFile::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    parseProprietaryInformation(apduResponse->getDataOut(), getCalypsoCard());
}

void CmdCardSelectFile::parseProprietaryInformation(
    const std::vector<uint8_t>& dataOut,
    const std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    const std::vector<uint8_t>& proprietaryInformation = getProprietaryInformation(dataOut);
    const uint8_t sfi = proprietaryInformation[CalypsoCardConstant::SEL_SFI_OFFSET];
    const uint8_t fileType = proprietaryInformation[CalypsoCardConstant::SEL_TYPE_OFFSET];

    if (fileType == CalypsoCardConstant::FILE_TYPE_MF ||
        fileType == CalypsoCardConstant::FILE_TYPE_DF) {

        std::shared_ptr<DirectoryHeader> directoryHeader =
            createDirectoryHeader(proprietaryInformation, calypsoCard);
        calypsoCard->setDirectoryHeader(directoryHeader);

    } else if (fileType == CalypsoCardConstant::FILE_TYPE_EF) {

        std::shared_ptr<FileHeaderAdapter> fileHeader =
            createFileHeader(proprietaryInformation, calypsoCard);
        calypsoCard->setFileHeader(sfi, fileHeader);

    } else {

        throw IllegalStateException(StringUtils::format("Unknown file type: %02Xh", fileType));
    }
}

bool CmdCardSelectFile::isSessionBufferUsed() const
{
    return false;
}

const std::vector<uint8_t> CmdCardSelectFile::getProprietaryInformation(
    const std::vector<uint8_t>& dataOut)
{
    std::vector<uint8_t> proprietaryInformation;
    const std::map<const int, const std::vector<uint8_t>> tags =
        BerTlvUtil::parseSimple(dataOut, true);

    const auto& it = tags.find(TAG_PROPRIETARY_INFORMATION);

    if (it == tags.end()) {

        throw IllegalStateException("Proprietary information: tag not found.");
    }

    proprietaryInformation = it->second;

    Assert::getInstance().isEqual(proprietaryInformation.size(), 23, "proprietaryInformation");

    return proprietaryInformation;
}

const std::shared_ptr<DirectoryHeader> CmdCardSelectFile::createDirectoryHeader(
    const std::vector<uint8_t>& proprietaryInformation,
    const std::shared_ptr<CalypsoCardAdapter> calypsoCard)

{
    std::vector<uint8_t> accessConditions(CalypsoCardConstant::SEL_AC_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_AC_OFFSET,
                      accessConditions,
                      0,
                      CalypsoCardConstant::SEL_AC_LENGTH);

    std::vector<uint8_t> keyIndexes(CalypsoCardConstant::SEL_NKEY_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_NKEY_OFFSET,
                      keyIndexes,
                      0,
                      CalypsoCardConstant::SEL_NKEY_LENGTH);

    const uint8_t dfStatus = proprietaryInformation[CalypsoCardConstant::SEL_DF_STATUS_OFFSET];

    const int lidOffset =
        calypsoCard->getProductType() == CalypsoCard::ProductType::PRIME_REVISION_2 ?
            CalypsoCardConstant::SEL_LID_OFFSET_REV2 : CalypsoCardConstant::SEL_LID_OFFSET;

    const uint8_t lid = ByteArrayUtil::extractShort(proprietaryInformation, lidOffset);

    return DirectoryHeaderAdapter::builder()
               ->lid(lid)
                .accessConditions(accessConditions)
                .keyIndexes(keyIndexes)
                .dfStatus(dfStatus)
                .kvc(WriteAccessLevel::PERSONALIZATION,
                     proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET])
                .kvc(WriteAccessLevel::LOAD,
                     proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET + 1])
                .kvc(WriteAccessLevel::DEBIT,
                     proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET + 2])
                .kif(WriteAccessLevel::PERSONALIZATION,
                     proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET])
                .kif(WriteAccessLevel::LOAD,
                     proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET + 1])
                .kif(WriteAccessLevel::DEBIT,
                     proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET + 2])
                .build();
}

const std::shared_ptr<FileHeaderAdapter> CmdCardSelectFile::createFileHeader(
    const std::vector<uint8_t>& proprietaryInformation,
    const std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    const ElementaryFile::Type fileType =
        getEfTypeFromCardValue(proprietaryInformation[CalypsoCardConstant::SEL_EF_TYPE_OFFSET]);

    int recordSize;
    int recordsNumber;

    if (fileType == ElementaryFile::Type::BINARY) {

        recordSize = ByteArrayUtil::extractInt(proprietaryInformation,
                                               CalypsoCardConstant::SEL_REC_SIZE_OFFSET,
                                               2,
                                               false);
        recordsNumber = 1;

    } else {

        recordSize = proprietaryInformation[CalypsoCardConstant::SEL_REC_SIZE_OFFSET];
        recordsNumber = proprietaryInformation[CalypsoCardConstant::SEL_NUM_REC_OFFSET];
    }

    std::vector<uint8_t> accessConditions(CalypsoCardConstant::SEL_AC_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_AC_OFFSET,
                      accessConditions,
                      0,
                      CalypsoCardConstant::SEL_AC_LENGTH);

    std::vector<uint8_t> keyIndexes(CalypsoCardConstant::SEL_NKEY_LENGTH);
    System::arraycopy(proprietaryInformation,
                      CalypsoCardConstant::SEL_NKEY_OFFSET,
                      keyIndexes,
                      0,
                      CalypsoCardConstant::SEL_NKEY_LENGTH);

    const uint8_t dfStatus = proprietaryInformation[CalypsoCardConstant::SEL_DF_STATUS_OFFSET];

    const uint16_t sharedReference =
        ByteArrayUtil::extractShort(proprietaryInformation,
                                    CalypsoCardConstant::SEL_DATA_REF_OFFSET);

    const int lidOffset =
        calypsoCard->getProductType() == CalypsoCard::ProductType::PRIME_REVISION_2 ?
            CalypsoCardConstant::SEL_LID_OFFSET_REV2 : CalypsoCardConstant::SEL_LID_OFFSET;

    const uint16_t lid = ByteArrayUtil::extractShort(proprietaryInformation, lidOffset);

    return FileHeaderAdapter::builder()
               ->lid(lid)
                .recordsNumber(recordsNumber)
                .recordSize(recordSize)
                .type(fileType)
                .accessConditions(Arrays::copyOf(accessConditions, accessConditions.size()))
                .keyIndexes(Arrays::copyOf(keyIndexes, keyIndexes.size()))
                .dfStatus(dfStatus)
                .sharedReference(sharedReference)
                .build();
}

ElementaryFile::Type CmdCardSelectFile::getEfTypeFromCardValue(const uint8_t efType)
{
    if (efType == CalypsoCardConstant::EF_TYPE_BINARY) {

        return ElementaryFile::Type::BINARY;

    } else if (efType == CalypsoCardConstant::EF_TYPE_LINEAR) {

        return ElementaryFile::Type::LINEAR;

    } else if (efType == CalypsoCardConstant::EF_TYPE_CYCLIC) {

        return ElementaryFile::Type::CYCLIC;

    } else if (efType == CalypsoCardConstant::EF_TYPE_SIMULATED_COUNTERS) {

        return ElementaryFile::Type::SIMULATED_COUNTERS;

    } else if  (efType == CalypsoCardConstant::EF_TYPE_COUNTERS) {

        return ElementaryFile::Type::COUNTERS;

    } else {

        throw IllegalStateException("Unknown EF Type: " + efType);
    }
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
