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

#include "CmdCardGetDataEfList.h"

/* Keyple Card Calypso */
#include "ApduRequestAdapter.h"
#include "CalypsoCardConstant.h"
#include "CardDataAccessException.h"
#include "FileHeaderAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const int CmdCardGetDataEfList::DESCRIPTORS_OFFSET = 2;
const int CmdCardGetDataEfList::DESCRIPTOR_DATA_OFFSET = 2;
const int CmdCardGetDataEfList::DESCRIPTOR_DATA_SFI_OFFSET = 2;
const int CmdCardGetDataEfList::DESCRIPTOR_TAG_LENGTH = 8;
const int CmdCardGetDataEfList::DESCRIPTOR_DATA_LENGTH = 6;
const CalypsoCardCommand CmdCardGetDataEfList::mCommand = CalypsoCardCommand::GET_DATA;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataEfList::STATUS_TABLE = initStatusTable();

CmdCardGetDataEfList::CmdCardGetDataEfList(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            0x00,
                            0xC0,
                            0x00)));
}

bool CmdCardGetDataEfList::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataEfList::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6A88,
              std::make_shared<StatusProperties>("Data object not found (optional mode not " \
                                                 "available).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardGetDataEfList::getStatusTable() const
{
    return STATUS_TABLE;
}

const std::map<const std::shared_ptr<FileHeaderAdapter>, const uint8_t>
    CmdCardGetDataEfList::getEfHeaders() const
{
    const std::vector<uint8_t> rawList = getApduResponse()->getDataOut();
    std::map<const std::shared_ptr<FileHeaderAdapter>, const uint8_t> fileHeaderToSfiMap;
    const int nbFiles = rawList[1] / DESCRIPTOR_TAG_LENGTH;

    for (int i = 0; i < nbFiles; i++) {
        fileHeaderToSfiMap.insert({
            createFileHeader(
                Arrays::copyOfRange(
                    rawList,
                    DESCRIPTORS_OFFSET + (i * DESCRIPTOR_TAG_LENGTH) + DESCRIPTOR_DATA_OFFSET,
                    DESCRIPTORS_OFFSET
                        + (i * DESCRIPTOR_TAG_LENGTH)
                        + DESCRIPTOR_DATA_OFFSET
                        + DESCRIPTOR_DATA_LENGTH)),
            rawList[
                DESCRIPTORS_OFFSET
                    + (i * DESCRIPTOR_TAG_LENGTH)
                    + DESCRIPTOR_DATA_OFFSET
                    + DESCRIPTOR_DATA_SFI_OFFSET]});
        }

    return fileHeaderToSfiMap;
}

const std::shared_ptr<FileHeaderAdapter> CmdCardGetDataEfList::createFileHeader(
    const std::vector<uint8_t>& efDescriptorByteArray) const
{
    ElementaryFile::Type efType;

    if (efDescriptorByteArray[3] == CalypsoCardConstant::EF_TYPE_LINEAR) {
        efType = ElementaryFile::Type::LINEAR;
    } else if (efDescriptorByteArray[3] == CalypsoCardConstant::EF_TYPE_CYCLIC) {
        efType = ElementaryFile::Type::CYCLIC;
    } else if (efDescriptorByteArray[3] == CalypsoCardConstant::EF_TYPE_COUNTERS) {
        efType = ElementaryFile::Type::COUNTERS;
    } else if (efDescriptorByteArray[3] == CalypsoCardConstant::EF_TYPE_BINARY) {
        efType = ElementaryFile::Type::BINARY;
    } else if (efDescriptorByteArray[3] == CalypsoCardConstant::EF_TYPE_SIMULATED_COUNTERS) {
        efType = ElementaryFile::Type::SIMULATED_COUNTERS;
    } else {
        throw IllegalStateException("Unexpected EF type");
    }

    return FileHeaderAdapter::builder()
               ->lid(efDescriptorByteArray[0] << 8 | (efDescriptorByteArray[1] & 0xFF))
                .type(efType)
                .recordSize(efDescriptorByteArray[4])
                .recordsNumber(efDescriptorByteArray[5])
                .build();
}

}
}
}
