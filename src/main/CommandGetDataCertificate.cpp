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

#include "keyple/card/calypso/CommandGetDataCertificate.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandGetDataCertificate::STATUS_TABLE = [] {
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

CommandGetDataCertificate::CommandGetDataCertificate(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    bool isCardCertificate,
    bool isFirstPart)
: Command(CardCommandRef::GET_DATA, nullptr, transactionContext, commandContext)
, mIsCardCertificate(isCardCertificate)
, mIsFirstPart(isFirstPart)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();

    std::uint8_t p1;
    std::uint8_t p2;

    if (isCardCertificate) {
        p1 = CalypsoCardConstant::TAG_CARD_CERTIFICATE_MSB;
        p2 = CalypsoCardConstant::TAG_CARD_CERTIFICATE_LSB;
    } else {
        p1 = CalypsoCardConstant::TAG_CA_CERTIFICATE_MSB;
        p2 = CalypsoCardConstant::TAG_CA_CERTIFICATE_LSB;
    }

    if (!isFirstPart) {
        p2++;
    }

    /* APDU Case 2 - always outside secure session */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass, getCommandRef().getInstructionByte(), p1, p2)));

    if (isCardCertificate) {
        addSubName("CARD_CERTIFICATE");
    } else {
        addSubName("CA_CERTIFICATE");
    }
}

void
CommandGetDataCertificate::finalizeRequest()
{
    /* NOP */
}

bool
CommandGetDataCertificate::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandGetDataCertificate::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandGetDataCertificate::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);

    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
    std::vector<std::uint8_t> certificateBytes;

    if (mIsFirstPart) {
        /*
         * Extract the certificate bytes, skipping the 5-byte tag and length
         * prefix.
         */
        certificateBytes = std::vector<std::uint8_t>(
            dataOut.size() - CalypsoCardConstant::TAG_CERTIFICATE_HEADER_SIZE);
        System::arraycopy(
            dataOut,
            CalypsoCardConstant::TAG_CERTIFICATE_HEADER_SIZE,
            certificateBytes,
            0,
            dataOut.size() - CalypsoCardConstant::TAG_CERTIFICATE_HEADER_SIZE);
    } else {
        /*
         * For subsequent parts, the entire dataOut is assumed to be the
         * certificate data.
         */
        certificateBytes = dataOut;
    }

    if (mIsCardCertificate) {
        getTransactionContext()->getCard()->addCardCertificateBytes(
            certificateBytes, mIsFirstPart);
    } else {
        getTransactionContext()->getCard()->addCaCertificateBytes(
            certificateBytes, mIsFirstPart);
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandGetDataCertificate::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
