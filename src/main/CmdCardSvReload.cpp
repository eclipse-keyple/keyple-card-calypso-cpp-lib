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

#include "CmdCardSvReload.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CalypsoCardClass.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityDataException.h"
#include "CardSessionBufferOverflowException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const CalypsoCardCommand CmdCardSvReload::mCommand = CalypsoCardCommand::SV_RELOAD;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSvReload::STATUS_TABLE = initStatusTable();

CmdCardSvReload::CmdCardSvReload(const std::shared_ptr<CalypsoCard> calypsoCard,
                                 const int amount,
                                 const uint8_t kvc,
                                 const std::vector<uint8_t>& date,
                                 const std::vector<uint8_t>& time,
                                 const std::vector<uint8_t>& free)
: AbstractCardCommand(mCommand)
{
    if (amount < -8388608 || amount > 8388607) {
        throw IllegalArgumentException("Amount is outside allowed boundaries (-8388608 <= amount " \
                                       "<=  8388607)");
    }

    if (date.empty() || time.empty() || free.empty()) {
        throw IllegalArgumentException("date, time and free cannot be null");
    }

    if (date.size() != 2 || time.size() != 2 || free.size() != 2) {
        throw IllegalArgumentException("date, time and free must be 2-byte arrays");
    }

    /* Keeps a copy of these fields until the builder is finalized */
    mCalypsoCard = calypsoCard;

    /*
     * Handle the dataIn size with signatureHi length according to card revision (3.2 rev have a
     * 10-byte signature)
     */
    mDataIn = std::vector<uint8_t>(18 + (mCalypsoCard->isExtendedModeSupported() ? 10 : 5));

    /* dataIn[0] will be filled in at the finalization phase */
    mDataIn[1] = date[0];
    mDataIn[2] = date[1];
    mDataIn[3] = free[0];
    mDataIn[4] = kvc;
    mDataIn[5] = free[1];
    mDataIn[6] = ((amount >> 16) & 0xFF);
    mDataIn[7] = ((amount >> 8) & 0xFF);
    mDataIn[8] = (amount & 0xFF);
    mDataIn[9] = time[0];
    mDataIn[10] = time[1];
    /* mDataIn[11]..mDataIn[11+7+sigLen] will be filled in at the finalization phase */
}

void CmdCardSvReload::finalizeCommand(const std::vector<uint8_t>& reloadComplementaryData)
{
    if ((mCalypsoCard->isExtendedModeSupported() && reloadComplementaryData.size() != 20) ||
        (!mCalypsoCard->isExtendedModeSupported() && reloadComplementaryData.size() != 15)) {
        throw IllegalArgumentException("Bad SV prepare load data length.");
    }

    const uint8_t p1 = reloadComplementaryData[4];
    const uint8_t p2 = reloadComplementaryData[5];

    mDataIn[0] = reloadComplementaryData[6];
    System::arraycopy(reloadComplementaryData, 0, mDataIn, 11, 4);
    System::arraycopy(reloadComplementaryData, 7, mDataIn, 15, 3);
    System::arraycopy(reloadComplementaryData, 10, mDataIn, 18, reloadComplementaryData.size()-10);

    const auto adapter = std::dynamic_pointer_cast<CalypsoCardAdapter>(mCalypsoCard);
    const uint8_t cardClass = adapter->getCardClass() == CalypsoCardClass::LEGACY ?
                                  CalypsoCardClass::LEGACY_STORED_VALUE.getValue() :
                                  CalypsoCardClass::ISO.getValue();

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cardClass,
                            mCommand.getInstructionByte(),
                            p1,
                            p2,
                            mDataIn)));
}

const std::vector<uint8_t> CmdCardSvReload::getSvReloadData() const
{
    std::vector<uint8_t> svReloadData(15);

    svReloadData[0] = mCommand.getInstructionByte();

    /*
     * svReloadData[1,2] / P1P2 not set because ignored
     * Lc is 5 bytes longer in revision 3.2
     */
    svReloadData[3] = mCalypsoCard->isExtendedModeSupported() ? 0x1C : 0x17;

    /* Appends the fixed part of dataIn */
    System::arraycopy(mDataIn, 0, svReloadData, 4, 11);

    return svReloadData;
}

bool CmdCardSvReload::isSessionBufferUsed() const
{
    return true;
}

CmdCardSvReload& CmdCardSvReload::setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
    if (dataOut.size() != 0 && dataOut.size() != 3 && dataOut.size() != 6) {
        throw IllegalStateException("Bad length in response to SV Reload command.");
    }

    return *this;
}

const std::vector<uint8_t> CmdCardSvReload::getSignatureLo() const
{
    return getApduResponse()->getDataOut();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSvReload::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session.",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("Transaction counter is 0 or SV TNum is FFFEh or" \
                                                 " FFFFh.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6988,
              std::make_shared<StatusProperties>("Incorrect signatureHi.",
                                                 typeid(CardSecurityDataException))});
    m.insert({0x6200,
              std::make_shared<StatusProperties>("Successful execution, response data postponed " \
                                                 "until session closing.",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardSvReload::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
