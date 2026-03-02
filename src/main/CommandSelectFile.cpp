/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/CommandSelectFile.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/DirectoryHeaderAdapter.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/BerTlvUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/SelectFileException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::Assert;
using keyple::core::util::BerTlvUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::SelectFileException;

const int CommandSelectFile::TAG_PROPRIETARY_INFORMATION = 0x85;
const CardCommandRef CommandSelectFile::mCommandRef
    = CardCommandRef::SELECT_FILE;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandSelectFile::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6A82,
              std::make_shared<StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6119,
              std::make_shared<StatusProperties>(
                  "Correct execution (ISO7816 T=0)", typeid(nullptr))}});
        return m;
    }();

CommandSelectFile::CommandSelectFile(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    SelectFileControl selectFileControl)
: Command(
      CardCommandRef::SELECT_FILE,
      std::unique_ptr<int>(new int(25)),
      transactionContext,
      commandContext)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();

    std::uint8_t p1;
    std::uint8_t p2;
    std::vector<std::uint8_t> selectData = {0x00, 0x00};

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
        throw IllegalStateException(
            "Unsupported SelectFileControl: ");  // FIXME +
                                                 // selectFileControl.name()
    }

    /* APDU Case 4 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass,
            mCommandRef.getInstructionByte(),
            p1,
            p2,
            selectData,
            0x00)));

    addSubName("Select file control: x");  // FIXME: selectFileControl
}

CommandSelectFile::CommandSelectFile(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint16_t lid)
: Command(
      CardCommandRef::SELECT_FILE,
      std::unique_ptr<int>(new int(25)),
      transactionContext,
      commandContext)
{
    CalypsoCardClass calypsoCardClass = CalypsoCardClass::UNKNOWN;
    CalypsoCard::ProductType productType;
    bool forceRevision1Settings;

    if (transactionContext->getCard() != nullptr) {
        std::shared_ptr<CalypsoCardAdapter> calypsoCard
            = transactionContext->getCard();
        calypsoCardClass = calypsoCard->getCardClass();
        productType = calypsoCard->getProductType();
        forceRevision1Settings = calypsoCard->isLegacyCase1();
    } else {
        calypsoCardClass = CalypsoCardClass::ISO;
        productType = CalypsoCard::ProductType::PRIME_REVISION_3;
        forceRevision1Settings = false;
    }

    /*
     * Handle the REV1 case.
     * CL-KEY-KIFSF.1.
     * If legacy and rev2 then 02h else if legacy then 08h else 09h.
     */
    std::uint8_t p1;

    if (calypsoCardClass == CalypsoCardClass::LEGACY) {
        if (productType == CalypsoCard::ProductType::PRIME_REVISION_1
            || forceRevision1Settings) {
            p1 = 0x08;
        } else {
            p1 = 0x02;
        }

    } else {
        p1 = 0x09;
    }

    const std::vector<std::uint8_t> dataIn
        = ByteArrayUtil::extractBytes(lid, 2);

    /* APDU Case 4 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            calypsoCardClass.getValue(),
            mCommandRef.getInstructionByte(),
            p1,
            0x00,
            dataIn,
            0x00)));

    addSubName(std::string("LID: ") + HexUtil::toHex(dataIn) + "h");
}

void
CommandSelectFile::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandSelectFile::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandSelectFile::synchronizeCryptoServiceBeforeCardProcessing()
{
    return !getCommandContext()->isSecureSessionOpen();
}

void
CommandSelectFile::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);

    try {
        Command::setApduResponseAndCheckStatus(apduResponse);

    } catch (const CardDataAccessException& e) {
        throw SelectFileException("File not found", e);
    }

    parseProprietaryInformation(
        apduResponse->getDataOut(), getTransactionContext()->getCard());
    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandSelectFile::getStatusTable() const
{
    return STATUS_TABLE;
}

void
CommandSelectFile::parseProprietaryInformation(
    const std::vector<std::uint8_t>& dataOut,
    std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    const std::vector<std::uint8_t> proprietaryInformation
        = getProprietaryInformation(dataOut);

    const std::uint8_t sfi
        = proprietaryInformation[CalypsoCardConstant::SEL_SFI_OFFSET];
    const std::uint8_t fileType
        = proprietaryInformation[CalypsoCardConstant::SEL_TYPE_OFFSET];

    switch (fileType) {
    case CalypsoCardConstant::FILE_TYPE_MF:
    case CalypsoCardConstant::FILE_TYPE_DF: {
        std::unique_ptr<DirectoryHeader> directoryHeader
            = createDirectoryHeader(proprietaryInformation, calypsoCard);
        calypsoCard->setDirectoryHeader(std::move(directoryHeader));
    } break;
    case CalypsoCardConstant::FILE_TYPE_EF: {
        std::shared_ptr<FileHeader> fileHeader
            = createFileHeader(proprietaryInformation, calypsoCard);
        calypsoCard->setFileHeader(
            sfi, std::dynamic_pointer_cast<FileHeaderAdapter>(fileHeader));
    } break;
    default:
        throw IllegalStateException(
            "Unsupported file type: " + HexUtil::toHex(fileType));
    }
}

std::vector<std::uint8_t>
CommandSelectFile::getProprietaryInformation(
    const std::vector<std::uint8_t>& dataOut)
{
    std::vector<std::uint8_t> proprietaryInformation;
    const std::map<const int, const std::vector<std::uint8_t>> tags
        = BerTlvUtil::parseSimple(dataOut, true);

    const auto it = tags.find(TAG_PROPRIETARY_INFORMATION);
    if (it == tags.end()) {
        throw IllegalStateException("Proprietary information tag not found");
    }

    proprietaryInformation = it->second;

    Assert::getInstance().isEqual(
        proprietaryInformation.size(), 23, "proprietaryInformation");

    return proprietaryInformation;
}

std::unique_ptr<DirectoryHeader>
CommandSelectFile::createDirectoryHeader(
    const std::vector<std::uint8_t>& proprietaryInformation,
    const std::shared_ptr<CalypsoCardAdapter>& calypsoCard)
{
    std::vector<std::uint8_t> accessConditions(
        CalypsoCardConstant::SEL_AC_LENGTH);
    System::arraycopy(
        proprietaryInformation,
        CalypsoCardConstant::SEL_AC_OFFSET,
        accessConditions,
        0,
        CalypsoCardConstant::SEL_AC_LENGTH);

    std::vector<std::uint8_t> keyIndexes(CalypsoCardConstant::SEL_NKEY_LENGTH);
    System::arraycopy(
        proprietaryInformation,
        CalypsoCardConstant::SEL_NKEY_OFFSET,
        keyIndexes,
        0,
        CalypsoCardConstant::SEL_NKEY_LENGTH);

    const std::uint8_t dfStatus
        = proprietaryInformation[CalypsoCardConstant::SEL_DF_STATUS_OFFSET];

    int lidOffset = calypsoCard->getProductType()
                            == CalypsoCard::ProductType::PRIME_REVISION_2
                        ? CalypsoCardConstant::SEL_LID_OFFSET_REV2
                        : CalypsoCardConstant::SEL_LID_OFFSET;

    std::uint16_t lid
        = ByteArrayUtil::extractShort(proprietaryInformation, lidOffset);

    return DirectoryHeaderAdapter::builder()
        ->lid(lid)
        .accessConditions(accessConditions)
        .keyIndexes(keyIndexes)
        .dfStatus(dfStatus)
        .kvc(
            WriteAccessLevel::PERSONALIZATION,
            proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET])
        .kvc(
            WriteAccessLevel::LOAD,
            proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET + 1])
        .kvc(
            WriteAccessLevel::DEBIT,
            proprietaryInformation[CalypsoCardConstant::SEL_KVCS_OFFSET + 2])
        .kif(
            WriteAccessLevel::PERSONALIZATION,
            proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET])
        .kif(
            WriteAccessLevel::LOAD,
            proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET + 1])
        .kif(
            WriteAccessLevel::DEBIT,
            proprietaryInformation[CalypsoCardConstant::SEL_KIFS_OFFSET + 2])
        .build();
}

std::shared_ptr<FileHeaderAdapter>
CommandSelectFile::createFileHeader(
    const std::vector<std::uint8_t>& proprietaryInformation,
    const std::shared_ptr<CalypsoCardAdapter>& calypsoCard)
{
    const ElementaryFile::Type fileType = getEfTypeFromCardValue(
        proprietaryInformation[CalypsoCardConstant::SEL_EF_TYPE_OFFSET]);

    int recordSize;
    int recordsNumber;

    if (fileType == ElementaryFile::Type::BINARY) {
        recordSize = ByteArrayUtil::extractInt(
            proprietaryInformation,
            CalypsoCardConstant::SEL_REC_SIZE_OFFSET,
            2,
            false);
        recordsNumber = 1;

    } else {
        recordSize
            = proprietaryInformation[CalypsoCardConstant::SEL_REC_SIZE_OFFSET];
        recordsNumber
            = proprietaryInformation[CalypsoCardConstant::SEL_NUM_REC_OFFSET];
    }

    std::vector<std::uint8_t> accessConditions(
        CalypsoCardConstant::SEL_AC_LENGTH);
    System::arraycopy(
        proprietaryInformation,
        CalypsoCardConstant::SEL_AC_OFFSET,
        accessConditions,
        0,
        CalypsoCardConstant::SEL_AC_LENGTH);

    std::vector<std::uint8_t> keyIndexes(CalypsoCardConstant::SEL_NKEY_LENGTH);
    System::arraycopy(
        proprietaryInformation,
        CalypsoCardConstant::SEL_NKEY_OFFSET,
        keyIndexes,
        0,
        CalypsoCardConstant::SEL_NKEY_LENGTH);

    const std::uint8_t dfStatus
        = proprietaryInformation[CalypsoCardConstant::SEL_DF_STATUS_OFFSET];

    std::uint16_t sharedReference = ByteArrayUtil::extractShort(
        proprietaryInformation, CalypsoCardConstant::SEL_DATA_REF_OFFSET);

    int lidOffset = calypsoCard->getProductType()
                            == CalypsoCard::ProductType::PRIME_REVISION_2
                        ? CalypsoCardConstant::SEL_LID_OFFSET_REV2
                        : CalypsoCardConstant::SEL_LID_OFFSET;

    std::uint16_t lid
        = ByteArrayUtil::extractShort(proprietaryInformation, lidOffset);

    return FileHeaderAdapter::builder()
        ->lid(lid)
        .recordsNumber(recordsNumber)
        .recordSize(recordSize)
        .type(fileType)
        .accessConditions(
            Arrays::copyOf(accessConditions, accessConditions.size()))
        .keyIndexes(Arrays::copyOf(keyIndexes, keyIndexes.size()))
        .dfStatus(dfStatus)
        .sharedReference(sharedReference)
        .build();
}

ElementaryFile::Type
CommandSelectFile::getEfTypeFromCardValue(std::uint8_t efType)
{
    ElementaryFile::Type fileType;

    switch (efType) {
    case CalypsoCardConstant::EF_TYPE_BINARY:
        fileType = ElementaryFile::Type::BINARY;
        break;
    case CalypsoCardConstant::EF_TYPE_LINEAR:
        fileType = ElementaryFile::Type::LINEAR;
        break;
    case CalypsoCardConstant::EF_TYPE_CYCLIC:
        fileType = ElementaryFile::Type::CYCLIC;
        break;
    case CalypsoCardConstant::EF_TYPE_SIMULATED_COUNTERS:
        fileType = ElementaryFile::Type::SIMULATED_COUNTERS;
        break;
    case CalypsoCardConstant::EF_TYPE_COUNTERS:
        fileType = ElementaryFile::Type::COUNTERS;
        break;
    default:
        throw IllegalStateException(
            "Unsupported EF Type: " + std::to_string(efType));
    }

    return fileType;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
