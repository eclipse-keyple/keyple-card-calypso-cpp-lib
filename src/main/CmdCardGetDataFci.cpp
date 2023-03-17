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

#include "CmdCardGetDataFci.h"

/* Keyple Card Calypso */
#include "ApduRequestAdapter.h"
#include "CardDataAccessException.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "BerTlvUtil.h"
#include "HexUtil.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const int CmdCardGetDataFci::TAG_DF_NAME = 0x84;
const int CmdCardGetDataFci::TAG_APPLICATION_SERIAL_NUMBER = 0xC7;
const int CmdCardGetDataFci::TAG_DISCRETIONARY_DATA = 0x53;
const CalypsoCardCommand CmdCardGetDataFci::mCommand = CalypsoCardCommand::GET_DATA;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataFci::STATUS_TABLE = initStatusTable();

CmdCardGetDataFci::CmdCardGetDataFci(const std::shared_ptr<CalypsoCardAdapter> calypsoCard)
: AbstractCardCommand(mCommand, 0, calypsoCard)
{
    buildCommand(calypsoCard->getCardClass());
}

CmdCardGetDataFci::CmdCardGetDataFci(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand, 0, nullptr)
{
    buildCommand(calypsoCardClass);
}

void CmdCardGetDataFci::buildCommand(const CalypsoCardClass calypsoCardClass)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            0x00,
                            0x6F,
                            0x00)));
}

bool CmdCardGetDataFci::isSessionBufferUsed() const
{
    return false;
}

void CmdCardGetDataFci::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    /*
     * Check the command status to determine if the DF has been invalidated
     * CL-INV-STATUS.1
     */
    if (getApduResponse()->getStatusWord() == 0x6283) {
        mLogger->debug("The response to the select application command status word indicates that" \
                       " the DF has been invalidated\n");
        mIsDfInvalidated = true;
    }

    /* Parse the raw data with the help of the TLV class */
    try {
        /* Init TLV object with the raw data and extract the FCI Template */
        const std::vector<uint8_t> responseData = getApduResponse()->getDataOut();

        /*
         * CL-SEL-TLVDATA.1
         * CL-TLV-VAR.1
         * CL-TLV-ORDER.1
         */
        const std::map<const int, const std::vector<uint8_t>> tags =
            BerTlvUtil::parseSimple(responseData, true);

        auto it = tags.find(TAG_DF_NAME);
        if (it == tags.end()) {
            mLogger->error("DF name tag (84h) not found\n");
            return;
        }

        mDfName = it->second;

        if (mDfName.size() < 5 || mDfName.size() > 16) {
            mLogger->error("Invalid DF name length: %. Should be between 5 and 16\n",
                           mDfName.size());
            return;
        }

        mLogger->debug("DF name = %\n", HexUtil::toHex(mDfName));

        it = tags.find(TAG_APPLICATION_SERIAL_NUMBER);
        if (it == tags.end()) {
            mLogger->error("Serial Number tag (C7h) not found\n");
            return;
        }

        mApplicationSN = it->second;

        /* CL-SEL-CSN.1 */
        if (mApplicationSN.size() != 8) {
            mLogger->error("Invalid application serial number length: %. Should be 8\n",
                           mApplicationSN.size());
            return;
        }

        mLogger->debug("Application Serial Number = %\n", HexUtil::toHex(mApplicationSN));

        it = tags.find(TAG_DISCRETIONARY_DATA);
        if (it == tags.end()) {
            mLogger->error("Discretionary data tag (53h) not found\n");
            return;
        }

        mDiscretionaryData = it->second;

        if (mDiscretionaryData.size() < 7) {
            mLogger->error("Invalid startup info length: %. Should be >= 7\n",
                           mDiscretionaryData.size());
            return;
        }

        mLogger->debug("Discretionary Data = %\n", HexUtil::toHex(mDiscretionaryData));

        /* All 3 main fields were retrieved */
        mIsValidCalypsoFCI = true;

    } catch (const Exception& e) {

        /* Silently ignore problems decoding TLV structure. Just log. */
        mLogger->debug("Error while parsing the FCI BER-TLV data structure (%)\n", e.getMessage());
    }

    getCalypsoCard()->initializeWithFci(shared_from_this());
}

bool CmdCardGetDataFci::isValidCalypsoFCI() const
{
    return mIsValidCalypsoFCI;
}

const std::vector<uint8_t>& CmdCardGetDataFci::getDfName() const
{
    return mDfName;
}

const std::vector<uint8_t>& CmdCardGetDataFci::getApplicationSerialNumber() const
{
    return mApplicationSN;
}

const std::vector<uint8_t>& CmdCardGetDataFci::getDiscretionaryData() const
{
    return mDiscretionaryData;
}

bool CmdCardGetDataFci::isDfInvalidated() const
{
    return mIsDfInvalidated;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataFci::initStatusTable()
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
    m.insert({0x6283,
              std::make_shared<StatusProperties>("Successful execution, FCI request and DF is " \
                                                 "invalidated.",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardGetDataFci::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
