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

#include "keyple/card/calypso/CommandSvGet.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
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

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandSvGet::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6982,
              std::make_shared<StatusProperties>(
                  "Security conditions not fulfilled",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied (a store value operation was "
                  "already done in the current session)",
                  typeid(CardAccessForbiddenException))},
             {0x6A81,
              std::make_shared<StatusProperties>(
                  "Incorrect P1 or P2", typeid(CardIllegalParameterException))},
             {0x6A86,
              std::make_shared<StatusProperties>(
                  "Le inconsistent with P2",
                  typeid(CardIllegalParameterException))},
             {0x6D00,
              std::make_shared<StatusProperties>(
                  "SV function not present",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandSvGet::CommandSvGet(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    SvOperation svOperation,
    bool useExtendedMode)
: Command(
      CardCommandRef::SV_GET,
      std::unique_ptr<int>(
          new int(computeExpectedResponseLength(svOperation, useExtendedMode))),
      transactionContext,
      commandContext)
{
    const std::uint8_t cla
        = transactionContext->getCard()->getCardClass()
                  == CalypsoCardClass::LEGACY
              ? CalypsoCardClass::LEGACY_STORED_VALUE.getValue()
              : CalypsoCardClass::ISO.getValue();

    const std::uint8_t p1 = useExtendedMode ? 0x01 : 0x00;
    const std::uint8_t p2 = svOperation == SvOperation::RELOAD ? 0x07 : 0x09;

    /* APDU Case 2 */
    const int* le = getExpectedResponseLength();
    if (le == nullptr) {
        setApduRequest(
            std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                cla, getCommandRef().getInstructionByte(), p1, p2)));
    } else {
        setApduRequest(
            std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                cla, getCommandRef().getInstructionByte(), p1, p2, *le)));
    }

    addSubName("Operation: " + std::to_string(static_cast<int>(svOperation)));

    mHeader.resize(4);
    mHeader[0] = getCommandRef().getInstructionByte();
    mHeader[1] = p1;
    mHeader[2] = p2;
    mHeader[3] = le == nullptr ? 0 : *le;
}

void
CommandSvGet::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandSvGet::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandSvGet::synchronizeCryptoServiceBeforeCardProcessing()
{
    return false;
}

void
CommandSvGet::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);

    const std::vector<std::uint8_t> cardResponse = apduResponse->getDataOut();
    std::uint8_t currentKvc;
    int transactionNumber;
    int balance;
    std::vector<std::uint8_t> loadLog;
    std::vector<std::uint8_t> debitLog;

    switch (cardResponse.size()) {
    case 0x21: /* Compatibility mode, Reload */
    case 0x1E: /* Compatibility mode, Debit or Undebit */
        currentKvc = cardResponse[0];
        transactionNumber
            = ByteArrayUtil::extractInt(cardResponse, 1, 2, false);
        balance = ByteArrayUtil::extractInt(cardResponse, 8, 3, true);

        if (cardResponse.size() == 0x21) {
            /* Reload */
            loadLog
                = Arrays::copyOfRange(cardResponse, 11, cardResponse.size());
            debitLog = {};
        } else {
            /* Debit */
            loadLog = {};
            debitLog
                = Arrays::copyOfRange(cardResponse, 11, cardResponse.size());
        }
        break;
    case 0x3D: /* Revision 3.2 mode */
        currentKvc = cardResponse[8];
        transactionNumber
            = ByteArrayUtil::extractInt(cardResponse, 9, 2, false);
        balance = ByteArrayUtil::extractInt(cardResponse, 17, 3, true);
        loadLog = Arrays::copyOfRange(cardResponse, 20, 42);
        debitLog = Arrays::copyOfRange(cardResponse, 42, cardResponse.size());
        break;
    default:
        throw IllegalStateException(
            "SV Get response is not the correct length. Expected: 30/33/61, "
            "Actual: "
            + std::to_string(cardResponse.size()));
    }

    std::shared_ptr<CalypsoCardAdapter> calypsoCard
        = getTransactionContext()->getCard();
    calypsoCard->setSvData(
        currentKvc,
        mHeader,
        apduResponse->getApdu(),
        balance,
        transactionNumber);

    if (!loadLog.empty()) {
        calypsoCard->addCyclicContent(
            CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI, loadLog);
    }

    if (!debitLog.empty()) {
        calypsoCard->addCyclicContent(
            CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI, debitLog);
    }

    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandSvGet::getStatusTable() const
{
    return STATUS_TABLE;
}

int
CommandSvGet::computeExpectedResponseLength(
    SvOperation svOperation, bool useExtendedMode)
{
    if (useExtendedMode) {
        return 0x3D;

    } else {
        return svOperation == SvOperation::RELOAD ? 0x21 : 0x1E;
    }
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
