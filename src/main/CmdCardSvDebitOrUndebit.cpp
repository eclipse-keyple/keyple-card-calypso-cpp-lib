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

#include "CmdCardSvDebitOrUndebit.h"

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

const int CmdCardSvDebitOrUndebit::SV_POSTPONED_DATA_IN_SESSION = 0x6200;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSvDebitOrUndebit::STATUS_TABLE = initStatusTable();

CmdCardSvDebitOrUndebit::CmdCardSvDebitOrUndebit(const bool isDebitCommand,
                                                 const CalypsoCardClass calypsoCardClass,
                                                 const int amount,
                                                 const uint8_t kvc,
                                                 const std::vector<uint8_t>& date,
                                                 const std::vector<uint8_t>& time,
                                                 const bool isExtendedModeAllowed)
: AbstractCardCommand(isDebitCommand ? CalypsoCardCommand::SV_DEBIT :
                                       CalypsoCardCommand::SV_UNDEBIT,
                      0),
  /* Keeps a copy of these fields until the command is finalized */
  mCalypsoCardClass(calypsoCardClass),
  mIsExtendedModeAllowed(isExtendedModeAllowed)
{
    /*
     * @see Calypso Layer ID 8.02 (200108)
     * CL-SV-DEBITVAL.1
     */
    if (amount < 0 || amount > 32767) {
        throw IllegalArgumentException("Amount is outside allowed boundaries (0 <= amount <= " \
                                       "32767)");
    }

    if (date.empty() || time.empty()) {
        throw IllegalArgumentException("date and time cannot be null");
    }

    if (date.size() != 2 || time.size() != 2) {
        throw IllegalArgumentException("date and time must be 2-byte arrays");
    }

    /*
     * Handle the dataIn size with signatureHi length according to card product type (3.2 rev have a
     * 10-byte signature)
     */
    mDataIn = std::vector<uint8_t>(15 + (isExtendedModeAllowed ? 10 : 5));

    /* mDataIn[0] will be filled in at the finalization phase */
    const short amountShort =
        isDebitCommand ? static_cast<short>(-amount) : static_cast<short>(amount);
    mDataIn[1] = ((amountShort >> 8) & 0xFF);
    mDataIn[2] = (amountShort & 0xFF);
    mDataIn[3] = date[0];
    mDataIn[4] = date[1];
    mDataIn[5] = time[0];
    mDataIn[6] = time[1];
    mDataIn[7] = kvc;
    /* mDataIn[8]..dataIn[8+7+sigLen] will be filled in at the finalization phase */
}

void CmdCardSvDebitOrUndebit::finalizeCommand(
    const std::vector<uint8_t>& debitOrUndebitComplementaryData)
{
    if ((mIsExtendedModeAllowed && debitOrUndebitComplementaryData.size() != 20) ||
        (!mIsExtendedModeAllowed && debitOrUndebitComplementaryData.size() != 15)) {
        throw IllegalArgumentException("Bad SV prepare load data length.");
    }

    const uint8_t p1 = debitOrUndebitComplementaryData[4];
    const uint8_t p2 = debitOrUndebitComplementaryData[5];

    mDataIn[0] = debitOrUndebitComplementaryData[6];
    System::arraycopy(debitOrUndebitComplementaryData, 0, mDataIn, 8, 4);
    System::arraycopy(debitOrUndebitComplementaryData, 7, mDataIn, 12, 3);
    System::arraycopy(debitOrUndebitComplementaryData,
                      10,
                      mDataIn,
                      15,
                      debitOrUndebitComplementaryData.size() - 10);

    const uint8_t cardClass = mCalypsoCardClass == CalypsoCardClass::LEGACY ?
                                  CalypsoCardClass::LEGACY_STORED_VALUE.getValue() :
                                  CalypsoCardClass::ISO.getValue();

    auto apduRequest = std::make_shared<ApduRequestAdapter>(
                           ApduUtil::build(cardClass,
                                           getCommandRef().getInstructionByte(),
                                           p1,
                                           p2,
                                           mDataIn));
    apduRequest->addSuccessfulStatusWord(SV_POSTPONED_DATA_IN_SESSION);
    setApduRequest(apduRequest);
}

const std::vector<uint8_t> CmdCardSvDebitOrUndebit::getSvDebitOrUndebitData() const
{
    std::vector<uint8_t> svDebitOrUndebitData(12);

    svDebitOrUndebitData[0] = getCommandRef().getInstructionByte();

    /*
     * svDebitOrUndebitData[1,2] / P1P2 not set because ignored
     * Lc is 5 bytes longer in product type 3.2
     */
    svDebitOrUndebitData[3] = mIsExtendedModeAllowed ? 0x19 : 0x14;

    /* Appends the fixed part of dataIn */
    System::arraycopy(mDataIn, 0, svDebitOrUndebitData, 4, 8);

    return svDebitOrUndebitData;
}

bool CmdCardSvDebitOrUndebit::isSessionBufferUsed() const
{
    return true;
}

CmdCardSvDebitOrUndebit& CmdCardSvDebitOrUndebit::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
    if (dataOut.size() != 0 && dataOut.size() != 3 && dataOut.size() != 6) {
        throw IllegalStateException("Bad length in response to SV Debit/Undebit command.");
    }

    return *this;
}

const std::vector<uint8_t> CmdCardSvDebitOrUndebit::getSignatureLo() const
{
    return getApduResponse()->getDataOut();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSvDebitOrUndebit::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({SV_POSTPONED_DATA_IN_SESSION,
              std::make_shared<StatusProperties>("Successful execution, response data postponed " \
                                                 "until session closing.",
                                                 typeid(nullptr))});
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

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardSvDebitOrUndebit::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
