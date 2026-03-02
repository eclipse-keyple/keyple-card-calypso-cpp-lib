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

#include "keyple/card/calypso/CommandPutData.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardSessionBufferOverflowException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::UnsupportedOperationException;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandPutData::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6400,
              std::make_shared<StatusProperties>(
                  "Too many modifications in session",
                  typeid(CardSessionBufferOverflowException))},
             {0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported", typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  "Security conditions not fulfilled",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Access forbidden", typeid(CardAccessForbiddenException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Lc not compatible with P1P2",
                  typeid(CardIllegalParameterException))},
             {0x6A87,
              std::make_shared<StatusProperties>(
                  "Incorrect incoming data",
                  typeid(CardIllegalParameterException))},
             {0x6A88,
              std::make_shared<StatusProperties>(
                  "Data object not found", typeid(CardDataAccessException))},
             {0x6A8A,
              std::make_shared<StatusProperties>(
                  "Incorrect AID", typeid(CardIllegalParameterException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1, P2", typeid(CardIllegalParameterException))},
             {0x6D00,
              std::make_shared<StatusProperties>(
                  "Command Put Data not supported",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandPutData::CommandPutData(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    PutDataTag tag,
    bool isFirstPart,
    const std::vector<std::uint8_t>& data)
: Command(CardCommandRef::PUT_DATA, 0, transactionContext, commandContext)
, mTag(tag)
, mData(data)
, mIsFirstPart(isFirstPart)
{
    std::uint8_t tagMsb;
    std::uint8_t tagLsb;
    std::vector<std::uint8_t> dataIn;

    switch (tag) {
    case PutDataTag::CARD_KEY_PAIR:
        tagMsb = CalypsoCardConstant::TAG_CARD_KEY_PAIR_MSB;
        tagLsb = CalypsoCardConstant::TAG_CARD_KEY_PAIR_LSB;
        dataIn = data;
        break;
    case PutDataTag::CARD_CERTIFICATE:
        tagMsb = CalypsoCardConstant::TAG_CARD_CERTIFICATE_MSB;
        tagLsb = isFirstPart
                     ? CalypsoCardConstant::TAG_CARD_CERTIFICATE_LSB
                     : CalypsoCardConstant::TAG_CARD_CERTIFICATE_LSB + 1;
        if (isFirstPart) {
            dataIn = CalypsoCardConstant::TAG_CARD_CERTIFICATE_HEADER;
            dataIn.insert(
                dataIn.end(),
                std::make_move_iterator(data.begin()),
                std::make_move_iterator(data.end()));
        } else {
            dataIn = data;
        }
        break;
    case PutDataTag::CA_CERTIFICATE:
        tagMsb = CalypsoCardConstant::TAG_CA_CERTIFICATE_MSB;
        tagLsb = isFirstPart ? CalypsoCardConstant::TAG_CA_CERTIFICATE_LSB
                             : CalypsoCardConstant::TAG_CA_CERTIFICATE_LSB + 1;
        if (isFirstPart) {
            dataIn = CalypsoCardConstant::TAG_CA_CERTIFICATE_HEADER;
            dataIn.insert(
                dataIn.end(),
                std::make_move_iterator(data.begin()),
                std::make_move_iterator(data.end()));
        } else {
            dataIn = data;
        }
        break;
    default:
        throw UnsupportedOperationException(
            "Unsupported PutDataTag: " + std::to_string(static_cast<int>(tag)));
    }

    /* APDU Case 3 - always outside secure session */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            tagMsb,
            tagLsb,
            dataIn)));
}

void
CommandPutData::finalizeRequest()
{
    /* NOP */
}

bool
CommandPutData::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandPutData::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandPutData::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);

    if (mTag == PutDataTag::CARD_KEY_PAIR) {
        getTransactionContext()->getCard()->setCardPublicKey(
            Arrays::copyOf(mData, CalypsoCardConstant::CARD_PUBLIC_KEY_SIZE));

    } else if (mTag == PutDataTag::CARD_CERTIFICATE) {
        getTransactionContext()->getCard()->addCardCertificateBytes(
            mData, mIsFirstPart);

    } else if (mTag == PutDataTag::CA_CERTIFICATE) {
        getTransactionContext()->getCard()->addCaCertificateBytes(
            mData, mIsFirstPart);
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandPutData::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
