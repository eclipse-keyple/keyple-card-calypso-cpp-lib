/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CmdCardCloseSession.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CardAccessForbiddenException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityDataException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const CalypsoCardCommand CmdCardCloseSession::mCommand = CalypsoCardCommand::CLOSE_SESSION;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardCloseSession::STATUS_TABLE = initStatusTable();

CmdCardCloseSession::CmdCardCloseSession(const std::shared_ptr<CalypsoCard> calypsoCard,
                                         const bool ratificationAsked,
                                         const std::vector<uint8_t> terminalSessionSignature)
: AbstractCardCommand(mCommand), mCalypsoCard(calypsoCard)
{
    /* The optional parameter terminalSessionSignature could contain 4 or 8 bytes */
    if (!terminalSessionSignature.empty() &&
        terminalSessionSignature.size() != 4 &&
        terminalSessionSignature.size() != 8) {
        throw IllegalArgumentException("Invalid terminal sessionSignature: " +
                                       ByteArrayUtil::toHex(terminalSessionSignature));
    }

    const uint8_t p1 = ratificationAsked ? 0x80 : 0x00;

    /*
     * Case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    const uint8_t le = 0;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(
                std::dynamic_pointer_cast<CalypsoCardAdapter>(calypsoCard)
                    ->getCardClass().getValue(),
                mCommand.getInstructionByte(),
                p1,
                0x00,
                terminalSessionSignature,
                le)));
}

CmdCardCloseSession::CmdCardCloseSession(const std::shared_ptr<CalypsoCard> calypsoCard)
: AbstractCardCommand(mCommand), mCalypsoCard(calypsoCard)
{
    /* CL-CSS-ABORTCMD.1 */
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(
                std::dynamic_pointer_cast<CalypsoCardAdapter>(calypsoCard)
                    ->getCardClass().getValue(),
                mCommand.getInstructionByte(),
                0x00,
                0x00,
                0)));
}

bool CmdCardCloseSession::isSessionBufferUsed() const
{
    return false;
}

CmdCardCloseSession& CmdCardCloseSession::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    const std::vector<uint8_t> responseData = getApduResponse()->getDataOut();

    if (mCalypsoCard->isExtendedModeSupported()) {
        /* 8-byte signature */
        if (responseData.size() == 8) {
            /* Signature only */
            mSignatureLo = Arrays::copyOfRange(responseData, 0, 8);
            mPostponedData = std::vector<uint8_t>(0);
        } else if (responseData.size() == 12) {
            /* Signature + 3 postponed bytes (+1) */
            mSignatureLo = Arrays::copyOfRange(responseData, 4, 12);
            mPostponedData = Arrays::copyOfRange(responseData, 1, 4);
        } else if (responseData.size() == 15) {
            /* Signature + 6 postponed bytes (+1) */
            mSignatureLo = Arrays::copyOfRange(responseData, 7, 15);
            mPostponedData = Arrays::copyOfRange(responseData, 1, 7);
        } else {
            if (responseData.size() != 0) {
            throw IllegalArgumentException("Unexpected length in response to CloseSecureSession " \
                                           "command: " +
                                           std::to_string(responseData.size()));
            }

            /* Session abort case */
            mSignatureLo = std::vector<uint8_t>(0);
            mPostponedData = std::vector<uint8_t>(0);
        }
    } else {
        /* 4-byte signature */
        if (responseData.size() == 4) {
            /* Signature only */
            mSignatureLo = Arrays::copyOfRange(responseData, 0, 4);
            mPostponedData = std::vector<uint8_t>(0);
        } else if (responseData.size() == 8) {
            /* Signature + 3 postponed bytes (+1) */
            mSignatureLo = Arrays::copyOfRange(responseData, 4, 8);
            mPostponedData = Arrays::copyOfRange(responseData, 1, 4);
        } else if (responseData.size() == 11) {
            /* Signature + 6 postponed bytes (+1) */
            mSignatureLo = Arrays::copyOfRange(responseData, 7, 11);
            mPostponedData = Arrays::copyOfRange(responseData, 1, 7);
        } else {
            if (responseData.size() != 0) {
            throw IllegalArgumentException("Unexpected length in response to CloseSecureSession " \
                                           "command: " +
                                           std::to_string(responseData.size()));
            }

            /* Session abort case */
            mSignatureLo = std::vector<uint8_t>(0);
            mPostponedData = std::vector<uint8_t>(0);
        }
    }

    return *this;
}

const std::vector<uint8_t>& CmdCardCloseSession::getSignatureLo() const
{
    return mSignatureLo;
}

const std::vector<uint8_t>& CmdCardCloseSession::getPostponedData() const
{
    return mPostponedData;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardCloseSession::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc signatureLo not supported (e.g. Lc=4 with a " \
                                                 "Revision 3.2 mode for Open Secure Session).",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 signatureLo not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6988,
              std::make_shared<StatusProperties>("incorrect signatureLo.",
                                                 typeid(CardSecurityDataException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("No session was opened.",
                                                 typeid(CardAccessForbiddenException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardCloseSession::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
