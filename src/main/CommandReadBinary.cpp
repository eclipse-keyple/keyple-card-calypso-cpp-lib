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

#include "keyple/card/calypso/CommandReadBinary.hpp"

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IndexOutOfBoundsException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IndexOutOfBoundsException;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandReadBinary::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6981,
              std::make_shared<StatusProperties>(
                  "Incorrect EF type: not a Binary EF",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  "Security conditions not fulfilled (PIN code not presented, "
                  "encryption required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Access forbidden (Never access mode)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<StatusProperties>(
                  std::string("Incorrect file type: the Current File is not an")
                      + "EF Supersedes 6981h",
                  typeid(CardDataAccessException))},
             {0x6A82,
              std::make_shared<StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Offset not in the file (offset overflow)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "P1 value not supported",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandReadBinary::CommandReadBinary(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t sfi,
    int offset,
    int length)
: Command(
      CardCommandRef::READ_BINARY,
      std::unique_ptr<int>(new int(length)),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mOffset(offset)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();
    mIsPreOpenMode
        = transactionContext->getCard() != nullptr
          && transactionContext->getCard()->getPreOpenWriteAccessLevel()
                 != WriteAccessLevel::UNKOWN;

    std::uint8_t msb = static_cast<std::uint8_t>(
        offset >> std::numeric_limits<std::uint8_t>::digits);
    std::uint8_t lsb = static_cast<std::uint8_t>(offset & 0xFF);

    /*
     * 100xxxxx : 'xxxxx' = SFI of the EF to select.
     * 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
     */
    const std::uint8_t p1 = msb > 0 ? msb : (0x80 + sfi);

    /* APDU Case 2 */
    setApduRequestInBestEffortMode(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass, getCommandRef().getInstructionByte(), p1, lsb, length)));

    addSubName(
        std::string("SFI: ") + HexUtil::toHex(sfi) + "h," + "Offset: "
        + std::to_string(offset) + "," + "Length: " + std::to_string(length));
}

void
CommandReadBinary::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandReadBinary::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandReadBinary::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (!getCommandContext()->isSecureSessionOpen()) {
        return true; /* Nothing to synchronize */
    }

    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    if (!mIsPreOpenMode) {
        return false;
    }

    /* Pre-open mode without encryption in secure session */
    if (!isCryptoServiceSynchronized()) {
        const std::vector<std::uint8_t> anticipatedApduResponse
            = buildAnticipatedResponse();
        if (anticipatedApduResponse.empty()) {
            const std::string sfiHex = HexUtil::toHex(mSfi);
            mLogger->warn(
                std::string("Unable to determine anticipated APDU response ")
                    + "because the record or some records have not been read "
                    + "beforehand [command={}, sfi={}, offset={}, length={}]",
                getName(),
                sfiHex,
                mOffset,
                getExpectedResponseLength());
            return false;
        }

        mAnticipatedDataOut = Arrays::copyOf(
            anticipatedApduResponse, anticipatedApduResponse.size() - 2);
        updateTerminalSessionIfNeeded(anticipatedApduResponse);
    }

    return true;
}

std::vector<std::uint8_t>
CommandReadBinary::buildAnticipatedResponse() const
{
    std::shared_ptr<ElementaryFile> ef
        = getTransactionContext()->getCard()->getFileBySfi(mSfi);
    if (ef == nullptr) {
        return {};
    }

    try {
        const std::vector<std::uint8_t> content = ef->getData()->getContent(
            1, mOffset, static_cast<uint8_t>(*getExpectedResponseLength()));
        std::vector<std::uint8_t> apdu(*getExpectedResponseLength() + 2);
        /* Record content */
        System::arraycopy(content, 0, apdu, 0, *getExpectedResponseLength());
        /* SW 9000 */
        apdu[*getExpectedResponseLength()] = 0x90;
        return apdu;

    } catch (const IndexOutOfBoundsException& e) {
        /* NOP */
    }

    return {};
}

void
CommandReadBinary::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    if (!setApduResponseAndCheckStatusInBestEffortMode(apduResponse)) {
        return;
    }

    getTransactionContext()->getCard()->setContent(
        mSfi, 1, apduResponse->getDataOut(), mOffset);
    if (!isCryptoServiceSynchronized()) {
        updateTerminalSessionIfNeeded();
    } else if (
        getCommandContext()->isSecureSessionOpen() && mIsPreOpenMode
        && !Arrays::equals(apduResponse->getDataOut(), mAnticipatedDataOut)) {
        throw CardSecurityContextException(
            "Data out does not match the anticipated data out",
            CardCommandRef::READ_BINARY);
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandReadBinary::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
