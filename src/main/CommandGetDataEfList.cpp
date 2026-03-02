/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding         * copyright ownership.
 *                                      *
 *                                                                                                *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                   *
 **************************************************************************************************/

#include "keyple/card/calypso/CommandGetDataEfList.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::exception::IllegalStateException;

const int CommandGetDataEfList::DESCRIPTORS_OFFSET = 2;
const int CommandGetDataEfList::DESCRIPTOR_DATA_OFFSET = 2;
const int CommandGetDataEfList::DESCRIPTOR_DATA_SFI_OFFSET = 2;
const int CommandGetDataEfList::DESCRIPTOR_TAG_LENGTH = 8;
const int CommandGetDataEfList::DESCRIPTOR_DATA_LENGTH = 6;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandGetDataEfList::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6A88,
              std::make_shared<StatusProperties>(
                  "Data object not found (optional mode not available)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardDataAccessException))}});
        return m;
    }();

CommandGetDataEfList::CommandGetDataEfList(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(CardCommandRef::GET_DATA, nullptr, transactionContext, commandContext)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();

    /* APDU Case 2 - always outside secure session */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass,
            getCommandRef().getInstructionByte(),
            CalypsoCardConstant::TAG_EF_LIST_MSB,
            CalypsoCardConstant::TAG_EF_LIST_LSB,
            0)));

    addSubName("EF_LIST");
}

void
CommandGetDataEfList::finalizeRequest()
{
    /* NOP */
}

bool
CommandGetDataEfList::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandGetDataEfList::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandGetDataEfList::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);

    const std::map<std::shared_ptr<FileHeaderAdapter>, std::uint8_t>
        fileHeaderToSfiMap = getEfHeaders();

    for (const auto& entry : fileHeaderToSfiMap) {
        getTransactionContext()->getCard()->setFileHeader(
            entry.second, entry.first);
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandGetDataEfList::getStatusTable() const
{
    return STATUS_TABLE;
}

std::map<std::shared_ptr<FileHeaderAdapter>, std::uint8_t>
CommandGetDataEfList::getEfHeaders()
{
    const std::vector<std::uint8_t> rawList = getApduResponse()->getDataOut();
    std::map<std::shared_ptr<FileHeaderAdapter>, std::uint8_t>
        fileHeaderToSfiMap;
    int nbFiles = rawList[1] / DESCRIPTOR_TAG_LENGTH;

    for (int i = 0; i < nbFiles; i++) {
        fileHeaderToSfiMap.insert(
            {createFileHeader(
                 Arrays::copyOfRange(
                     rawList,
                     DESCRIPTORS_OFFSET + (i * DESCRIPTOR_TAG_LENGTH)
                         + DESCRIPTOR_DATA_OFFSET,
                     DESCRIPTORS_OFFSET + (i * DESCRIPTOR_TAG_LENGTH)
                         + DESCRIPTOR_DATA_OFFSET + DESCRIPTOR_DATA_LENGTH)),
             rawList
                 [DESCRIPTORS_OFFSET + (i * DESCRIPTOR_TAG_LENGTH)
                  + DESCRIPTOR_DATA_OFFSET + DESCRIPTOR_DATA_SFI_OFFSET]});
    }

    return fileHeaderToSfiMap;
}

std::shared_ptr<FileHeaderAdapter>
CommandGetDataEfList::createFileHeader(
    const std::vector<std::uint8_t>& efDescriptorByteArray)
{
    ElementaryFile::Type efType;

    switch (efDescriptorByteArray[3]) {
    case CalypsoCardConstant::EF_TYPE_LINEAR:
        efType = ElementaryFile::Type::LINEAR;
        break;
    case CalypsoCardConstant::EF_TYPE_CYCLIC:
        efType = ElementaryFile::Type::CYCLIC;
        break;
    case CalypsoCardConstant::EF_TYPE_COUNTERS:
        efType = ElementaryFile::Type::COUNTERS;
        break;
    case CalypsoCardConstant::EF_TYPE_BINARY:
        efType = ElementaryFile::Type::BINARY;
        break;
    case CalypsoCardConstant::EF_TYPE_SIMULATED_COUNTERS:
        efType = ElementaryFile::Type::SIMULATED_COUNTERS;
        break;
    default:
        throw IllegalStateException(
            "Unexpected EF type: " + std::to_string(efDescriptorByteArray[3]));
    }

    return FileHeaderAdapter::builder()
        ->lid(ByteArrayUtil::extractShort(efDescriptorByteArray, 0))
        .type(efType)
        .recordSize(efDescriptorByteArray[4])
        .recordsNumber(efDescriptorByteArray[5])
        .build();
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
