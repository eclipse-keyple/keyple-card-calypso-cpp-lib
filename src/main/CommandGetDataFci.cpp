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

#include "keyple/card/calypso/CommandGetDataFci.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardClass.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/BerTlvUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::BerTlvUtil;
using keyple::core::util::HexUtil;

const int CommandGetDataFci::TAG_DF_NAME = 0x84;
const int CommandGetDataFci::TAG_APPLICATION_SERIAL_NUMBER = 0xC7;
const int CommandGetDataFci::TAG_DISCRETIONARY_DATA = 0x53;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandGetDataFci::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6A88,
              std::make_shared<StatusProperties>(
                  "Data object not found (optional mode not "
                  "available)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardDataAccessException))},
             {0x6283,
              std::make_shared<StatusProperties>(
                  "Successful execution, FCI request and DF is "
                  "invalidated",
                  typeid(nullptr))}});
        return m;
    }();

CommandGetDataFci::CommandGetDataFci(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(CardCommandRef::GET_DATA, nullptr, transactionContext, commandContext)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();

    /* APDU Case 2 - always outside secure session  */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass,
            getCommandRef().getInstructionByte(),
            CalypsoCardConstant::TAG_FCI_FOR_CURRENT_DF_MSB,
            CalypsoCardConstant::TAG_FCI_FOR_CURRENT_DF_LSB,
            0)));

    addSubName("FCI_FOR_CURRENT_DF");
}

void
CommandGetDataFci::finalizeRequest()
{
    /* NOP */
}

bool
CommandGetDataFci::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandGetDataFci::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandGetDataFci::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);

    /*
     * Check the command status to determine if the DF has been invalidated
     * CL-INV-STATUS.1
     */
    if (getApduResponse()->getStatusWord() == 0x6283) {
        mLogger->debug("DF invalidated\n");
        mIsDfInvalidated = true;
    }

    /* Parse the raw data with the help of the TLV class */
    try {
        /* Init TLV object with the raw data and extract the FCI Template */
        const std::vector<uint8_t> responseData
            = getApduResponse()->getDataOut();

        /*
         * CL-SEL-TLVDATA.1
         * CL-TLV-VAR.1
         * CL-TLV-ORDER.1
         */
        const std::map<const int, const std::vector<uint8_t>> tags
            = BerTlvUtil::parseSimple(responseData, true);

        auto it = tags.find(TAG_DF_NAME);
        if (it == tags.end()) {
            mLogger->error("DF name tag (84h) not found\n");
            return;
        }

        mDfName = it->second;

        if (mDfName.size() < 5 || mDfName.size() > 16) {
            mLogger->error(
                std::string("DF name is not the correct length (should be in")
                    + " range [5..16]) [actual=%]\n",
                mDfName.size());
            return;
        }

        mLogger->debug("DF name = %\n", HexUtil::toHex(mDfName));

        it = tags.find(TAG_APPLICATION_SERIAL_NUMBER);
        if (it == tags.end()) {
            mLogger->error("Serial number tag (C7h) not found\n");
            return;
        }

        mApplicationSN = it->second;

        /* CL-SEL-CSN.1 */
        if (mApplicationSN.size() != 8) {
            mLogger->error(
                std::string("Application serial number is not the correct ")
                    + "length (expected 8) [actual=%]\n",
                mApplicationSN.size());
            return;
        }

        mLogger->debug(
            "Application Serial Number = %\n", HexUtil::toHex(mApplicationSN));

        it = tags.find(TAG_DISCRETIONARY_DATA);
        if (it == tags.end()) {
            mLogger->error("Discretionary data tag (53h) not found\n");
            return;
        }

        mDiscretionaryData = it->second;

        if (mDiscretionaryData.size() < 7) {
            mLogger->error(
                std::string("Startup info is not the correct length (should")
                    + " be >= 7) [actual=%]\n",
                mDiscretionaryData.size());
            return;
        }

        mLogger->debug(
            "Discretionary Data = %\n", HexUtil::toHex(mDiscretionaryData));

        /* All 3 main fields were retrieved */
        mIsValidCalypsoFCI = true;

        mLogger->debug(
            "DF parsed [dfName=%, serialNumber=%, discretionaryData=%]\n",
            HexUtil::toHex(mDfName),
            HexUtil::toHex(mApplicationSN),
            HexUtil::toHex(mDiscretionaryData));

    } catch (const Exception& e) {
        /* Silently ignore problems decoding TLV structure. Just log. */
        mLogger->debug(
            "failed to parse FCI BER-TLV data structure [reason=%]\n",
            e.getMessage());
    }

    getTransactionContext()->getCard()->initializeWithFci(shared_from_this());
}

bool
CommandGetDataFci::isValidCalypsoFCI() const
{
    return mIsValidCalypsoFCI;
}

const std::vector<uint8_t>&
CommandGetDataFci::getDfName() const
{
    return mDfName;
}

const std::vector<uint8_t>&
CommandGetDataFci::getApplicationSerialNumber() const
{
    return mApplicationSN;
}

const std::vector<uint8_t>&
CommandGetDataFci::getDiscretionaryData() const
{
    return mDiscretionaryData;
}

bool
CommandGetDataFci::isDfInvalidated() const
{
    return mIsDfInvalidated;
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandGetDataFci::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
