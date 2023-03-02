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

#include "CardTransactionManagerAdapter.h"

#include <algorithm>
#include <sstream>

/* Calypsonet Terminal Calypso */
#include "CardIOException.h"
#include "CardSignatureNotVerifiableException.h"
#include "InconsistentDataException.h"
#include "ReaderIOException.h"
#include "SamIOException.h"
#include "SessionBufferOverflowException.h"
#include "UnauthorizedKeyException.h"
#include "UnexpectedCommandStatusException.h"
#include "UnexpectedStatusWordException.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"
#include "ApduRequestSpi.h"
#include "CardBrokenCommunicationException.h"
#include "CardResponseApi.h"
#include "ReaderBrokenCommunicationException.h"

/* Keyple Card Calypso */
#include "CalypsoCardConstant.h"
#include "CalypsoCardUtilAdapter.h"
#include "CalypsoSamCommandException.h"
#include "CalypsoSamSecurityDataException.h"
#include "CardCommandException.h"
#include "CardRequestAdapter.h"
#include "CardSecurityDataException.h"
#include "CardSecuritySettingAdapter.h"
#include "CmdCardGetDataFci.h"
#include "CmdCardGetDataFcp.h"
#include "CmdCardInvalidate.h"
#include "CmdCardReadRecords.h"
#include "CmdCardRehabilitate.h"
#include "CmdCardSelectFile.h"

/* Keyple Core Util */
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "CmdCardRatificationBuilder.h"
#include "HexUtil.h"
#include "IllegalStateException.h"
#include "KeypleAssert.h"
#include "KeypleStd.h"
#include "MapUtils.h"
#include "System.h"
#include "UnsupportedOperationException.h"


namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

/* CARD TRANSACTION MANAGER ADAPTER ------------------------------------------------------------- */
const std::string CardTransactionManagerAdapter::PATTERN_1_BYTE_HEX = "%020Xh";

const std::string CardTransactionManagerAdapter::MSG_CARD_READER_COMMUNICATION_ERROR =
    "A communication error with the card reader occurred ";
const std::string CardTransactionManagerAdapter::MSG_CARD_COMMUNICATION_ERROR =
    "A communication error with the card occurred ";
const std::string CardTransactionManagerAdapter::MSG_CARD_COMMAND_ERROR =
    "A card command error occurred ";

const std::string CardTransactionManagerAdapter::MSG_PIN_NOT_AVAILABLE =
    "PIN is not available for this card.";
const std::string CardTransactionManagerAdapter::MSG_CARD_SIGNATURE_NOT_VERIFIABLE =
    "Unable to verify the card signature associated to the successfully closed secure session.";
const std::string CardTransactionManagerAdapter::MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV =
      "Unable to verify the card signature associated to the SV operation.";

const std::string CardTransactionManagerAdapter::RECORD_NUMBER = "record number";
const std::string CardTransactionManagerAdapter::OFFSET = "offset";

const int CardTransactionManagerAdapter::SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;
const int CardTransactionManagerAdapter::APDU_HEADER_LENGTH = 5;


const std::shared_ptr<ApduResponseApi> CardTransactionManagerAdapter::RESPONSE_OK =
    std::make_shared<ApduResponseAdapter>(std::vector<uint8_t>({0x90, 0x00}));
const std::shared_ptr<ApduResponseApi> CardTransactionManagerAdapter::RESPONSE_OK_POSTPONED =
    std::make_shared<ApduResponseAdapter>(std::vector<uint8_t>({0x62, 0x00}));

CardTransactionManagerAdapter::CardTransactionManagerAdapter(
  const std::shared_ptr<ProxyReaderApi> cardReader,
  const std::shared_ptr<CalypsoCardAdapter> card,
  const std::shared_ptr<CardSecuritySettingAdapter> securitySetting)
: CommonTransactionManagerAdapter(
    card,
    std::dynamic_pointer_cast<CommonSecuritySettingAdapter<CardSecuritySettingAdapter>>(securitySetting),
    std::vector<std::vector<uint8_t>>()),
  mCardReader(cardReader),
  mCard(card),
  mSecuritySetting(securitySetting),
  mModificationsCounter(card->getModificationsCounter())
{
    if (securitySetting != nullptr && securitySetting->getControlSam() != nullptr) {
        /* Secure operations mode */
        mControlSamTransactionManager =
            std::make_shared<CardControlSamTransactionManagerAdapter>(card,
                                                                      securitySetting,
                                                                      getTransactionAuditData());

    } else {
        /* Non-secure operations mode */
        mControlSamTransactionManager = nullptr;
    }
}

const std::shared_ptr<CardReader> CardTransactionManagerAdapter::getCardReader() const
{
    return std::dynamic_pointer_cast<CardReader>(mCardReader);
}

const std::shared_ptr<CalypsoCard> CardTransactionManagerAdapter::getCalypsoCard() const
{
    return mCard;
}

const std::shared_ptr<CardSecuritySetting> CardTransactionManagerAdapter::getCardSecuritySetting()
    const
{
    return getSecuritySetting();
}

void CardTransactionManagerAdapter::checkControlSam() const
{
    if (mControlSamTransactionManager == nullptr) {
        throw IllegalStateException("Control SAM is not set.");
    }
}

void CardTransactionManagerAdapter::processSamPreparedCommands()
{
    if (mControlSamTransactionManager != nullptr) {
        mControlSamTransactionManager->processCommands();
    }
}

void CardTransactionManagerAdapter::processAtomicOpening(
    std::vector<std::shared_ptr<AbstractApduCommand>>& cardCommands)
{
    if (mSecuritySetting == nullptr) {
        throw IllegalStateException("No security settings are available.");
    }

    mCard->backupFiles();

    /*
     * Let's check if we have a read record command at the top of the command list.
     * If so, then the command is withdrawn in favour of its equivalent executed at the same
     * time as the open secure session command.
     * The sfi and record number to be read when the open secure session command is executed.
     * The default value is 0 (no record to read) but we will optimize the exchanges if a read
     * record command has been prepared.
     */
    uint8_t sfi = 0;
    uint8_t recordNumber = 0;

    if (!cardCommands.empty()) {
        const auto cardCommand = std::dynamic_pointer_cast<AbstractCardCommand>(cardCommands[0]);
        if (cardCommand->getCommandRef() == CalypsoCardCommand::READ_RECORDS &&
            std::dynamic_pointer_cast<CmdCardReadRecords>(cardCommand)->getReadMode() ==
                CmdCardReadRecords::ReadMode::ONE_RECORD) {
            sfi = std::dynamic_pointer_cast<CmdCardReadRecords>(cardCommand)->getSfi();
            recordNumber =
                std::dynamic_pointer_cast<CmdCardReadRecords>(cardCommand)->getFirstRecordNumber();
            cardCommands.erase(cardCommands.begin());
        }
    }

    /* Compute the SAM challenge and process all pending SAM commands */
    const std::vector<uint8_t> samChallenge = processSamGetChallenge();

    /* Build the card Open Secure Session command */
    auto cmdCardOpenSession =
        std::make_shared<CmdCardOpenSession>(
            mCard->getProductType(),
            static_cast<uint8_t>(static_cast<int>(mWriteAccessLevel) + 1),
            samChallenge,
            sfi,
            recordNumber,
            isExtendedModeAllowed());

    /* Add the "Open Secure Session" card command in first position */
    cardCommands.insert(cardCommands.begin(), cmdCardOpenSession);

    /* List of APDU requests to hold Open Secure Session and other optional commands */
    const std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests =
        getApduRequests(cardCommands);

    /* Wrap the list of c-APDUs into a card requets */
    auto cardRequest = std::make_shared<CardRequestAdapter>(apduRequests, true);

    mIsSessionOpen = true;

    /* Open a secure session, transmit the commands to the card and keep channel open */
    const std::shared_ptr<CardResponseApi> cardResponse =
        transmitCardRequest(cardRequest, ChannelControl::KEEP_OPEN);

    /* Retrieve the list of R-APDUs */
    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponses =
        cardResponse->getApduResponses();

    /* Parse all the responses and fill the CalypsoCard object with the command data */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCard,
                                                  cardCommands,
                                                  apduResponses,
                                                  true);
    } catch (const CardCommandException& e) {
        throw UnexpectedCommandStatusException(MSG_CARD_COMMAND_ERROR +
                                               "while processing the response to open session: " +
                                                e.getCommand().getName() +
                                                getTransactionAuditDataAsString(),
                                                std::make_shared<CardCommandException>(e));
    } catch (const InconsistentDataException& e) {
        throw InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
    }

    /* Build the "Digest Init" SAM command from card Open Session */

    /* The card KIF/KVC (KVC may be null for card Rev 1.0) */
    const std::shared_ptr<uint8_t> cardKif = cmdCardOpenSession->getSelectedKif();
    const std::shared_ptr<uint8_t> cardKvc = cmdCardOpenSession->getSelectedKvc();

    const std::string logCardKif = cardKif != nullptr ? std::to_string(*cardKif) : "null";
    const std::string logCardKvc = cardKvc != nullptr ? std::to_string(*cardKvc) : "null";
    mLogger->debug("processAtomicOpening => opening: CARD_CHALLENGE=%, CARD_KIF=%, CARD_KVC=%\n",
                   HexUtil::toHex(cmdCardOpenSession->getCardChallenge()),
                   logCardKif,
                   logCardKvc);

    const std::shared_ptr<uint8_t> kvc =
        mControlSamTransactionManager->computeKvc(mWriteAccessLevel, cardKvc);
    const std::shared_ptr<uint8_t> kif =
        mControlSamTransactionManager->computeKif(mWriteAccessLevel, cardKif, kvc);

    if (!mSecuritySetting->isSessionKeyAuthorized(kif, kvc)) {
        const std::string logKif = kif != nullptr ? std::to_string(*kif) : "null";
        const std::string logKvc = kvc != nullptr ? std::to_string(*kvc) : "null";
        throw UnauthorizedKeyException("Unauthorized key error: " \
                                       "KIF=" + logKif + ", " +
                                       "KVC=" + logKvc + " " +
                                       getTransactionAuditDataAsString());
    }

    /* Initialize a new SAM session. */
    mControlSamTransactionManager->initializeSession(apduResponses[0]->getDataOut(),
                                                     *kif,
                                                     *kvc,
                                                     false,
                                                     false);

    /*
     * Add all commands data to the digest computation. The first command in the list is the
     * open secure session command. This command is not included in the digest computation, so
     * we skip it and start the loop at index 1.
     */
    mControlSamTransactionManager->updateSession(apduRequests, apduResponses, 1);
}

void CardTransactionManagerAdapter::abortSecureSessionSilently()
{
    if (mIsSessionOpen) {

        try {
            processCancel();
        } catch (const RuntimeException& e) {
            mLogger->warn("An error occurred while aborting the current secure session: %",
                          e.getMessage());
        }

        mIsSessionOpen = false;
    }
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSetCounter(
    const uint8_t sfi, const uint8_t counterNumber, const int newValue)
{
    std::shared_ptr<int> oldValue;

    const std::shared_ptr<ElementaryFile> ef = mCard->getFileBySfi(sfi);
    if (ef != nullptr) {
        oldValue = ef->getData()->getContentAsCounterValue(counterNumber);
    }

    if (oldValue == nullptr) {
        throw IllegalStateException("The value for counter " + std::to_string(counterNumber) +
                                    " in file " + std::to_string(sfi) + " is not available");
    }

    const int delta = newValue - *oldValue;
    if (delta > 0) {
        mLogger->trace("Increment counter % (file %) from % to %\n",
                       counterNumber,
                       sfi,
                       newValue - delta,
                       newValue);

        prepareIncreaseCounter(sfi, counterNumber, delta);
    } else if (delta < 0) {
        mLogger->trace("Decrement counter % (file %) from % to %\n",
                       counterNumber,
                       sfi,
                       newValue - delta,
                       newValue);

        prepareDecreaseCounter(sfi, counterNumber, -delta);
    } else {
        mLogger->info("The counter % (SFI %) is already set to the desired value %\n",
                       counterNumber,
                       sfi,
                       newValue);
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareIncreaseOrDecreaseCounters(
    const bool isDecreaseCommand,
    const uint8_t sfi,
    const std::map<const int, const int>& counterNumberToIncDecValueMap)
{
    if (mCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3 &&
        mCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_2) {
        throw UnsupportedOperationException("The 'Increase/Decrease Multiple' commands are not " \
                                            "available for this card.");
    }

    Assert::getInstance().isInRange((int) sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(counterNumberToIncDecValueMap.size(),
                                    CalypsoCardConstant::NB_CNT_MIN,
                                    CalypsoCardConstant::NB_CNT_MAX,
                                    "counterNumberToIncDecValueMap");

    for (const auto& entry : counterNumberToIncDecValueMap) {
        Assert::getInstance().isInRange(entry.first,
                                        CalypsoCardConstant::NB_CNT_MIN,
                                        CalypsoCardConstant::NB_CNT_MAX,
                                        "counterNumberToIncDecValueMapKey")
                             .isInRange(entry.second,
                                        CalypsoCardConstant::CNT_VALUE_MIN,
                                        CalypsoCardConstant::CNT_VALUE_MAX,
                                        "counterNumberToIncDecValueMapValue");
    }

    const int nbCountersPerApdu = mCard->getPayloadCapacity() / 4;

    if (static_cast<int>(counterNumberToIncDecValueMap.size()) <= nbCountersPerApdu) {
        /* Create the command and add it to the list of commands */
        const std::map<const int, const int> dummy;
        mCardCommands.push_back(
            std::make_shared<CmdCardIncreaseOrDecreaseMultiple>(
                isDecreaseCommand,
                mCard->getCardClass(),
                sfi,
                dummy));
    } else {
        /*
         * The number of counters exceeds the payload capacity, let's split into several apdu c
         * ommands
         */
        int i = 0;
        std::map<const int, const int> map;

        for (const auto& entry : counterNumberToIncDecValueMap) {
            i++;
            map.insert({entry.first, entry.second});
            if (i == nbCountersPerApdu) {
                mCardCommands.push_back(
                    std::make_shared<CmdCardIncreaseOrDecreaseMultiple>(
                        isDecreaseCommand,
                        mCard->getCardClass(),
                        sfi,
                        map));
                i = 0;
                map.clear();
            }
        }

        if (!map.empty()) {
            mCardCommands.push_back(
                std::make_shared<CmdCardIncreaseOrDecreaseMultiple>(isDecreaseCommand,
                                                                    mCard->getCardClass(),
                                                                    sfi,
                                                                    map));
        }
    }

    return *this;
}

void CardTransactionManagerAdapter::processAtomicCardCommands(
    const std::vector<std::shared_ptr<AbstractApduCommand>> cardCommands,
    const ChannelControl channelControl)
{
    /* Get the list of C-APDU to transmit */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests = getApduRequests(cardCommands);

    /* Wrap the list of C-APDUs into a card request */
    std::shared_ptr<CardRequestSpi> cardRequest =
        std::make_shared<CardRequestAdapter>(apduRequests, true);

    /* Transmit the commands to the card */
    const std::shared_ptr<CardResponseApi> cardResponse =
        transmitCardRequest(cardRequest, channelControl);

    /* Retrieve the list of R-APDUs */
    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponses =
        cardResponse->getApduResponses();

    /*
     * If this method is invoked within a secure session, then add all commands data to the digest
     * computation.
     */
    if (mIsSessionOpen) {
        mControlSamTransactionManager->updateSession(apduRequests, apduResponses, 0);
    }

    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCard,
                                                  cardCommands,
                                                  apduResponses,
                                                  mIsSessionOpen);
    } catch (const CardCommandException& e) {
        throw UnexpectedCommandStatusException(MSG_CARD_COMMAND_ERROR +
                                               "while processing responses to card commands: " +
                                               e.getCommand().getName() +
                                               getTransactionAuditDataAsString(),
                                               std::make_shared<CardCommandException>(e));
    } catch (const InconsistentDataException& e) {
        throw InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
    }
}

void CardTransactionManagerAdapter::processAtomicClosing(
    const std::vector<std::shared_ptr<AbstractApduCommand>>& cardCommands,
    const bool isRatificationMechanismEnabled,
    const ChannelControl channelControl)
{
    /* Get the list of C-APDU to transmit */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests = getApduRequests(cardCommands);

    /* Build the expected APDU respones of the card commands */
    const std::vector<std::shared_ptr<ApduResponseApi>> expectedApduResponses =
        buildAnticipatedResponses(cardCommands);

    /* Add all commands data to the digest computation. */
    mControlSamTransactionManager->updateSession(apduRequests, expectedApduResponses, 0);

    /*
     * All SAM digest operations will now run at once.
     * Get Terminal Signature from the latest response.
     */
    const std::vector<uint8_t> sessionTerminalSignature = processSamSessionClosing();

    /* Build the last "Close Secure Session" card command */
    auto cmdCardCloseSession =
        std::make_shared<CmdCardCloseSession>(mCard,
                                              !isRatificationMechanismEnabled,
                                              sessionTerminalSignature);

    apduRequests.push_back(cmdCardCloseSession->getApduRequest());

    /* Add the card Ratification command if any */
    bool isRatificationCommandAdded;
    if (isRatificationMechanismEnabled &&
        std::dynamic_pointer_cast<CardReader>(mCardReader)->isContactless()) {
        /*
         * CL-RAT-CMD.1
         * CL-RAT-DELAY.1
         * CL-RAT-NXTCLOSE.1
         */
        apduRequests.push_back(
            CmdCardRatificationBuilder::getApduRequest(mCard->getCardClass()));
        isRatificationCommandAdded = true;
    } else {
        isRatificationCommandAdded = false;
    }

    /* Transfer card commands */
    auto cardRequest = std::make_shared<CardRequestAdapter>(apduRequests, true);

    /* Transmit the commands to the card */
    std::shared_ptr<CardResponseApi> cardResponse;

    try {
        cardResponse = transmitCardRequest(cardRequest, channelControl);
    } catch (const CardIOException& e) {
        const auto cause = std::dynamic_pointer_cast<AbstractApduException>(e.getCause());
        cardResponse = cause->getCardResponse();

        /*
         * The current exception may have been caused by a communication issue with the card
         * during the ratification command.
         * In this case, we do not stop the process and consider the Secure Session close. We'll
         * check the signature.
         * We should have one response less than requests.
         */
        if (!isRatificationCommandAdded ||
            cardResponse == nullptr ||
            cardResponse->getApduResponses().size() != apduRequests.size() - 1) {
            throw e;
        }
    }

    /* Retrieve the list of R-APDUs */
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses = cardResponse->getApduResponses();

    /* Remove response of ratification command if present */
    if (isRatificationCommandAdded && apduResponses.size() == cardCommands.size() + 2) {
        apduResponses.pop_back();
    }

    /* Retrieve response of "Close Secure Session" command if present */
    std::shared_ptr<ApduResponseApi> closeSecureSessionApduResponse = nullptr;
    if (apduResponses.size() == cardCommands.size() + 1) {
        closeSecureSessionApduResponse = apduResponses.back();
        apduResponses.pop_back();
    }

    /*
     * Check the commands executed before closing the secure session (only responses to these
     * commands will be taken into account)
     */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCard,
                                                  cardCommands,
                                                  apduResponses,
                                                  true);
    } catch (const CardCommandException& e) {
        throw UnexpectedCommandStatusException(MSG_CARD_COMMAND_ERROR +
                                               "while processing of responses preceding the close" \
                                               " of the session: " +
                                               e.getCommand().getName() +
                                               getTransactionAuditDataAsString(),
                                               std::make_shared<CardCommandException>(e));
    } catch (const InconsistentDataException& e) {
        throw InconsistentDataException(e.getMessage() + getTransactionAuditDataAsString());
    }


    mIsSessionOpen = false;

    /* Check the card's response to Close Secure Session */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCard,
                                                  cmdCardCloseSession,
                                                  closeSecureSessionApduResponse,
                                                  false);
    } catch (const CardSecurityDataException& e) {
        throw UnexpectedCommandStatusException("Invalid card session" +
                                              getTransactionAuditDataAsString(),
                                              std::make_shared<CardSecurityDataException>(e));
    } catch (const CardCommandException& e) {
        throw UnexpectedCommandStatusException(MSG_CARD_COMMAND_ERROR +
                                               "while processing the response to close session: " +
                                               e.getCommand().getName() +
                                               getTransactionAuditDataAsString(),
                                               std::make_shared<CardCommandException>(e));
    }

    /*
     * Check the card signature
     * CL-CSS-MACVERIF.1
     */
    processSamDigestAuthenticate(cmdCardCloseSession->getSignatureLo());

    /*
     * If necessary, we check the status of the SV after the session has been successfully closed.
     * CL-SV-POSTPON.1
     */
    if (isSvOperationCompleteOneTime()) {
        processSamSvCheck(cmdCardCloseSession->getPostponedData());
    }
}

int CardTransactionManagerAdapter::getCounterValue(const uint8_t sfi, const int counter)
{
    const std::shared_ptr<ElementaryFile> ef = mCard->getFileBySfi(sfi);
    if (ef != nullptr) {
        const std::shared_ptr<int> counterValue = ef->getData()->getContentAsCounterValue(counter);
        if (counterValue != nullptr) {
            return *counterValue;
        }
    }

    std::stringstream ss;
    ss << "Anticipated response. Unable to determine anticipated value of counter "
       << counter
       << " in EF sfi "
       << sfi;
    throw IllegalStateException(ss.str());
}

const std::map<const int, const int> CardTransactionManagerAdapter::getCounterValues(
    const uint8_t sfi, const std::vector<int>& counters)
{
    const std::shared_ptr<ElementaryFile> ef = mCard->getFileBySfi(sfi);
    if (ef != nullptr) {
        const std::map<const int, const int> allCountersValue = ef->getData()->getAllCountersValue();

        if (Arrays::containsAll(MapUtils::getKeySet(allCountersValue), counters)) {
            return allCountersValue;
        }
    }

    std::stringstream ss;
    ss << "Anticipated response. Unable to determine anticipated value of counters in EF sfi "
       << sfi;
    throw IllegalStateException(ss.str());
}

const std::shared_ptr<ApduResponseApi>
    CardTransactionManagerAdapter::buildAnticipatedIncreaseDecreaseResponse(
        const bool isDecreaseCommand, const int currentCounterValue, const int incDecValue)
{
    const int newValue = isDecreaseCommand ? currentCounterValue - incDecValue :
                                             currentCounterValue + incDecValue;

    /* Response = NNNNNN9000 */
    std::vector<uint8_t> response(5);
    response[0] = static_cast<uint8_t>((newValue & 0x00FF0000) >> 16);
    response[1] = static_cast<uint8_t>((newValue & 0x0000FF00) >> 8);
    response[2] = static_cast<uint8_t>(newValue & 0x000000FF);
    response[3] = 0x90;
    response[4] = 0x00;

    return std::make_shared<ApduResponseAdapter>(response);
}

const std::shared_ptr<ApduResponseApi>
    CardTransactionManagerAdapter::buildAnticipatedIncreaseDecreaseMultipleResponse(
        const bool isDecreaseCommand,
        const std::map<const int, const int>& counterNumberToCurrentValueMap,
        const std::map<const int, const int>& counterNumberToIncDecValueMap)
{
    /* Response = CCVVVVVV..CCVVVVVV9000 */
    std::vector<uint8_t> response(2 + counterNumberToIncDecValueMap.size() * 4);
    int index = 0;

    for (const auto& entry : counterNumberToIncDecValueMap) {
        response[index] = static_cast<uint8_t>(entry.first);
        int newCounterValue;
        if (isDecreaseCommand) {
            const auto it = counterNumberToCurrentValueMap.find(entry.first);
            newCounterValue = it->second - entry.second;
        } else {
            const auto it = counterNumberToCurrentValueMap.find(entry.first);
            newCounterValue = it->second + entry.second;
        }

        response[index + 1] = static_cast<uint8_t>((newCounterValue & 0x00FF0000) >> 16);
        response[index + 2] = static_cast<uint8_t>((newCounterValue & 0x0000FF00) >> 8);
        response[index + 3] = static_cast<uint8_t>(newCounterValue & 0x000000FF);
        index += 4;
    }

    response[index] = 0x90;
    response[index + 1] = 0x00;

    return std::make_shared<ApduResponseAdapter>(response);
}

const std::vector<std::shared_ptr<ApduResponseApi>>
    CardTransactionManagerAdapter::buildAnticipatedResponses(
        const std::vector<std::shared_ptr<AbstractApduCommand>>& cardCommands)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;

    if (!cardCommands.empty()) {
        for (const auto& command : cardCommands) {

            auto& commandRef = dynamic_cast<const CalypsoCardCommand&>(command->getCommandRef());
            if (commandRef == CalypsoCardCommand::INCREASE ||
                commandRef == CalypsoCardCommand::DECREASE) {

                auto cmdA = std::dynamic_pointer_cast<CmdCardIncreaseOrDecrease>(command);
                apduResponses.push_back(
                    buildAnticipatedIncreaseDecreaseResponse(
                        cmdA->getCommandRef() == CalypsoCardCommand::DECREASE,
                        getCounterValue(cmdA->getSfi(), cmdA->getCounterNumber()),
                        cmdA->getIncDecValue()));

            } else if (commandRef == CalypsoCardCommand::INCREASE_MULTIPLE ||
                       commandRef == CalypsoCardCommand::DECREASE_MULTIPLE) {

                auto cmdB = std::dynamic_pointer_cast<CmdCardIncreaseOrDecreaseMultiple>(command);
                const std::map<const int, const int>& counterNumberToIncDecValueMap =
                    cmdB->getCounterNumberToIncDecValueMap();
                apduResponses.push_back(
                    buildAnticipatedIncreaseDecreaseMultipleResponse(
                        cmdB->getCommandRef() == CalypsoCardCommand::DECREASE_MULTIPLE,
                        getCounterValues(cmdB->getSfi(),
                                         MapUtils::getKeySet(counterNumberToIncDecValueMap)),
                        counterNumberToIncDecValueMap));

            } else if (commandRef == CalypsoCardCommand::SV_RELOAD ||
                       commandRef == CalypsoCardCommand::SV_DEBIT ||
                       commandRef == CalypsoCardCommand::SV_UNDEBIT) {
                apduResponses.push_back(RESPONSE_OK_POSTPONED);

            } else {
                /* Append/Update/Write Record: response = 9000 */
                apduResponses.push_back(RESPONSE_OK);
            }
        }
    }

    return apduResponses;
}

CardTransactionManager& CardTransactionManagerAdapter::processOpening(
    const WriteAccessLevel writeAccessLevel)
{
    try {
        checkNoSession();

        /* CL-KEY-INDEXPO.1 */
        mWriteAccessLevel = writeAccessLevel;

        /* Create a sublist of AbstractCardCommand to be sent atomically */
        std::vector<std::shared_ptr<AbstractApduCommand>> cardAtomicCommands;

        for (const auto& apduCommand : mCardCommands) {

            const auto& command = std::dynamic_pointer_cast<AbstractCardCommand>(apduCommand);
            /* Check if the command is a modifying command */
            if (command->isSessionBufferUsed()) {
                mModificationsCounter -= computeCommandSessionBufferSize(command);
                if (mModificationsCounter < 0) {
                    checkMultipleSessionEnabled(command);

                    /* Process and intermedisate secure session with the current commands */
                    processAtomicOpening(cardAtomicCommands);
                    std::vector<std::shared_ptr<AbstractApduCommand>> empty;
                    processAtomicClosing(empty, false, ChannelControl::KEEP_OPEN);

                    /* Reset and update the buffer counter */
                    mModificationsCounter = mCard->getModificationsCounter();
                    mModificationsCounter -= computeCommandSessionBufferSize(command);

                    /* Clear the list */
                    cardAtomicCommands.clear();
                }
            }

            cardAtomicCommands.push_back(command);
        }

        processAtomicOpening(cardAtomicCommands);

        /* Sets the flag indicating that the commands have been executed */
        notifyCommandsProcessed();

        /* CL-SV-1PCSS.1 */
        mIsSvOperationInsideSession = false;

        return *this;

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

void CardTransactionManagerAdapter::checkMultipleSessionEnabled(
    std::shared_ptr<AbstractCardCommand> command) const
{
    /*
     * CL-CSS-REQUEST.1
     * CL-CSS-SMEXCEED.1
     * CL-CSS-INFOCSS.1
     */
    if (!mSecuritySetting->isMultipleSessionEnabled()) {
        throw SessionBufferOverflowException("ATOMIC mode error! This command would overflow the " \
                                             "card modifications buffer: " +
                                             command->getName() +
                                             getTransactionAuditDataAsString());
    }
}

void CardTransactionManagerAdapter::processCommandsOutsideSession(
    const ChannelControl channelControl)
{
    /* Card commands sent outside a Secure Session. No modifications buffer limitation */
    processAtomicCardCommands(mCardCommands, channelControl);

    /* Sets the flag indicating that the commands have been executed */
    notifyCommandsProcessed();

    /* If an SV transaction was performed, we check the signature returned by the card here  */
    if (isSvOperationCompleteOneTime()) {
        /* Execute all prepared SAM commands and check SV status. */
        processSamSvCheck(mCard->getSvOperationSignature());
    } else {
        /* Execute all prepared SAM commands. */
        processSamPreparedCommands();
    }
}

void CardTransactionManagerAdapter::processCommandsInsideSession()
{
    try {
        /* A session is open, we have to care about the card modifications buffer */
        std::vector<std::shared_ptr<AbstractApduCommand>> cardAtomicCommands;
        bool isAtLeastOneReadCommand = false;

        for (const auto& apduCommand : mCardCommands) {

            const auto& command = std::dynamic_pointer_cast<AbstractCardCommand>(apduCommand);

            /* Check if the command is a modifying command */
            if (command->isSessionBufferUsed()) {
                mModificationsCounter -= computeCommandSessionBufferSize(command);
                if (mModificationsCounter < 0) {
                    checkMultipleSessionEnabled(command);

                    /*
                     * Close the current secure session with the current commands and open a new one
                     */
                    if (isAtLeastOneReadCommand) {
                        processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);
                        cardAtomicCommands.clear();
                    }

                    processAtomicClosing(cardAtomicCommands, false, ChannelControl::KEEP_OPEN);
                    std::vector<std::shared_ptr<AbstractApduCommand>> empty;
                    processAtomicOpening(empty);

                    /* Reset and update the buffer counter */
                    mModificationsCounter = mCard->getModificationsCounter();
                    mModificationsCounter -= computeCommandSessionBufferSize(command);
                    isAtLeastOneReadCommand = false;

                    /* Clear the list */
                    cardAtomicCommands.clear();
                }
            } else {
                isAtLeastOneReadCommand = true;
            }
        }

        processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);

        /* Sets the flag indicating that the commands have been executed */
        notifyCommandsProcessed();

        processSamPreparedCommands();

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

const std::shared_ptr<CardSecuritySetting> CardTransactionManagerAdapter::getSecuritySetting() const
{
    return mSecuritySetting;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareComputeSignature(const any data)
{
    checkControlSam();

    mControlSamTransactionManager->prepareComputeSignature(data);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareVerifySignature(const any data)
{

    checkControlSam();

    mControlSamTransactionManager->prepareVerifySignature(data);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processCommands()
{
    finalizeSvCommandIfNeeded();

    if (mIsSessionOpen) {
        processCommandsInsideSession();
    } else {
        processCommandsOutsideSession(mChannelControl);
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processCardCommands()
{
    return processCommands();
}

CardTransactionManager& CardTransactionManagerAdapter::processClosing()
{
    try {
        checkSession();
        finalizeSvCommandIfNeeded();

        std::vector<std::shared_ptr<AbstractApduCommand>> cardAtomicCommands;
        bool isAtLeastOneReadCommand = false;

        for (const auto& apduCommand : mCardCommands) {

            const auto& command = std::dynamic_pointer_cast<AbstractCardCommand>(apduCommand);

            /* Check if the command is a modifying command */
            if (command->isSessionBufferUsed()) {
                mModificationsCounter -= computeCommandSessionBufferSize(command);
                if (mModificationsCounter < 0) {
                    checkMultipleSessionEnabled(command);

                    /*
                     * Close the current secure session with the current commands and open a new
                     * one.
                     */
                    if (isAtLeastOneReadCommand) {
                        processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);
                        cardAtomicCommands.clear();
                    }

                    processAtomicClosing(cardAtomicCommands, false, ChannelControl::KEEP_OPEN);
                    std::vector<std::shared_ptr<AbstractApduCommand>> empty;
                    processAtomicOpening(empty);

                   /* Reset and update the buffer counter */
                   mModificationsCounter = mCard->getModificationsCounter();
                   mModificationsCounter -= computeCommandSessionBufferSize(command);
                   isAtLeastOneReadCommand = false;

                   /* Clear the list */
                   cardAtomicCommands.clear();
                }

            } else {
                isAtLeastOneReadCommand = true;
            }

            cardAtomicCommands.push_back(command);
        }

        if (isAtLeastOneReadCommand) {
            processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);
            cardAtomicCommands.clear();
        }

        processAtomicClosing(cardAtomicCommands,
                             mSecuritySetting->isRatificationMechanismEnabled(),
                             mChannelControl);

        /* Sets the flag indicating that the commands have been executed */
        notifyCommandsProcessed();

        return *this;

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

CardTransactionManager& CardTransactionManagerAdapter::processCancel()
{
    checkSession();

    mCard->restoreFiles();

    /* Build the card Close Session command (in "abort" mode since no signature is provided) */
    auto cmdCardCloseSession = std::make_shared<CmdCardCloseSession>(mCard);

    /* Card ApduRequestAdapter List to hold close SecureSession command */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;
    apduRequests.push_back(cmdCardCloseSession->getApduRequest());

    /* Transfer card commands */
    const std::shared_ptr<CardRequestSpi> cardRequest =
        std::make_shared<CardRequestAdapter>(apduRequests, false);
    const std::shared_ptr<CardResponseApi> cardResponse =
        transmitCardRequest(cardRequest, mChannelControl);

    try {
        cmdCardCloseSession->parseApduResponse(cardResponse->getApduResponses()[0]);
    } catch (const CardCommandException& e) {
        throw UnexpectedCommandStatusException(MSG_CARD_COMMAND_ERROR +
                                               "while processing the response to close session: " +
                                               e.getCommand().getName() +
                                               getTransactionAuditDataAsString(),
                                               std::make_shared<CardCommandException>(e));
    }

    /* Sets the flag indicating that the commands have been executed */
    notifyCommandsProcessed();

    /*
     * Session is now considered closed regardless the previous state or the result of the abort
     * session command sent to the card.
     */
    mIsSessionOpen = false;

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processVerifyPin(
    const std::vector<uint8_t>& pin)
{
    try {
        Assert::getInstance().isEqual(pin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        if (!mCardCommands.empty()) {
            throw IllegalStateException("No commands should have been prepared prior to a PIN " \
                                        "submission.");
        }

        finalizeSvCommandIfNeeded();

        /* CL-PIN-PENCRYPT.1 */
        if (mSecuritySetting != nullptr && !mSecuritySetting->isPinPlainTransmissionEnabled()) {

            /* CL-PIN-GETCHAL.1 */
            mCardCommands.push_back(std::make_shared<CmdCardGetChallenge>(mCard->getCardClass()));

            /* Transmit and receive data with the card */
            processAtomicCardCommands(mCardCommands, ChannelControl::KEEP_OPEN);

            /* Sets the flag indicating that the commands have been executed */
            notifyCommandsProcessed();

            /* Get the encrypted PIN with the help of the SAM */
            std::vector<uint8_t> cipheredPin = processSamCardCipherPin(pin, std::vector<uint8_t>());

            mCardCommands.push_back(
                std::make_shared<CmdCardVerifyPin>(mCard->getCardClass(), true, cipheredPin));
        } else {
            mCardCommands.push_back(
                std::make_shared<CmdCardVerifyPin>(mCard->getCardClass(), false, pin));
        }

        /* Transmit and receive data with the card */
        processAtomicCardCommands(mCardCommands, mChannelControl);

        /* Sets the flag indicating that the commands have been executed */
        notifyCommandsProcessed();

        processSamPreparedCommands();

        return *this;

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::processSamCardCipherPin(
    const std::vector<uint8_t>& currentPin, const std::vector<uint8_t>& newPin)
{
    mControlSamTransactionManager->prepareGiveRandom();
    const std::shared_ptr<CmdSamCardCipherPin> cmdSamCardCipherPin =
        mControlSamTransactionManager->prepareCardCipherPin(currentPin, newPin);
    mControlSamTransactionManager->processCommands();

    return cmdSamCardCipherPin->getCipheredData();
}

CardTransactionManager& CardTransactionManagerAdapter::processChangePin(
    const std::vector<uint8_t>& newPin)
{
    try {
        Assert::getInstance().isEqual(newPin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        if (mIsSessionOpen) {
            throw IllegalStateException("'Change PIN' not allowed when a secure session is open.");
        }

        finalizeSvCommandIfNeeded();

        /* CL-PIN-MENCRYPT.1 */
        if (mSecuritySetting->isPinPlainTransmissionEnabled()) {

            /* Transmission in plain mode */
            if (mCard->getPinAttemptRemaining() >= 0) {
                mCardCommands.push_back(
                    std::make_shared<CmdCardChangePin>(mCard->getCardClass(), newPin));
            }
        } else {
            /* CL-PIN-GETCHAL.1 */
            mCardCommands.push_back(
                std::make_shared<CmdCardGetChallenge>(mCard->getCardClass()));

            /* Transmit and receive data with the card */
            processAtomicCardCommands(mCardCommands, ChannelControl::KEEP_OPEN);

            /* Sets the flag indicating that the commands have been executed */
            notifyCommandsProcessed();

            /* Get the encrypted PIN with the help of the SAM */
            std::vector<uint8_t> currentPin(4); /* All zeros as required */
            std::vector<uint8_t> newPinData = processSamCardCipherPin(currentPin, newPin);

            mCardCommands.push_back(
                std::make_shared<CmdCardChangePin>(mCard->getCardClass(), newPinData));
        }

        /* Transmit and receive data with the card */
        processAtomicCardCommands(mCardCommands, mChannelControl);

        /* Sets the flag indicating that the commands have been executed */
        notifyCommandsProcessed();

        processSamPreparedCommands();

        return *this;

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

CardTransactionManager& CardTransactionManagerAdapter::processChangeKey(const uint8_t keyIndex,
                                                                        const uint8_t newKif,
                                                                        const uint8_t newKvc,
                                                                        const uint8_t issuerKif,
                                                                        const uint8_t issuerKvc)
{
    if (mCard->getProductType() == CalypsoCard::ProductType::BASIC) {
        throw UnsupportedOperationException("The 'Change Key' command is not available for this " \
                                            "card.");
    }

    if (mIsSessionOpen) {
        throw IllegalStateException("'Change Key' not allowed when a secure session is open.");
    }

    Assert::getInstance().isInRange(keyIndex, 1, 3, "keyIndex");

    finalizeSvCommandIfNeeded();

    /* CL-KEY-CHANGE.1 */
    mCardCommands.push_back(std::make_shared<CmdCardGetChallenge>(mCard->getCardClass()));

    /* Transmit and receive data with the card */
    processAtomicCardCommands(mCardCommands, ChannelControl::KEEP_OPEN);

    /* Sets the flag indicating that the commands have been executed */
    notifyCommandsProcessed();

    /* Get the encrypted key with the help of the SAM */
    const std::vector<uint8_t> encryptedKey = processSamCardGenerateKey(issuerKif,
                                                                        issuerKvc,
                                                                        newKif,
                                                                        newKvc);

    mCardCommands.push_back(std::make_shared<CmdCardChangeKey>(mCard->getCardClass(),
                                                               keyIndex,
                                                               encryptedKey));

    /* Transmit and receive data with the card */
    processAtomicCardCommands(mCardCommands, mChannelControl);

    /* Sets the flag indicating that the commands have been executed */
    notifyCommandsProcessed();

    return *this;
}

const std::vector<uint8_t> CardTransactionManagerAdapter::processSamCardGenerateKey(
    const uint8_t issuerKif, const uint8_t issuerKvc, const uint8_t newKif, const uint8_t newKvc)
{
    mControlSamTransactionManager->prepareGiveRandom();
    const std::shared_ptr<CmdSamCardGenerateKey> cmdSamCardGenerateKey =
        mControlSamTransactionManager->prepareCardGenerateKey(issuerKif, issuerKvc, newKif, newKvc);
    mControlSamTransactionManager->processCommands();

    return cmdSamCardGenerateKey->getCipheredData();
}

const std::shared_ptr<CardResponseApi> CardTransactionManagerAdapter::transmitCardRequest(
    const std::shared_ptr<CardRequestSpi> cardRequest, const ChannelControl channelControl)
{
    /* Process card request */
    std::shared_ptr<CardResponseApi> cardResponse = nullptr;

    try {
        cardResponse = mCardReader->transmitCardRequest(cardRequest, channelControl);
    } catch (const ReaderBrokenCommunicationException& e) {
        saveTransactionAuditData(cardRequest, e.getCardResponse());
        throw ReaderIOException(MSG_CARD_READER_COMMUNICATION_ERROR +
                                MSG_WHILE_TRANSMITTING_COMMANDS +
                                getTransactionAuditDataAsString(),
                                std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        saveTransactionAuditData(cardRequest, e.getCardResponse());
        throw CardIOException(MSG_CARD_COMMUNICATION_ERROR +
                              MSG_WHILE_TRANSMITTING_COMMANDS +
                              getTransactionAuditDataAsString(),
                              std::make_shared<CardBrokenCommunicationException>(e));
    } catch (const UnexpectedStatusWordException& e) {
        mLogger->debug("A card command has failed: %\n", e.getMessage());
        cardResponse = e.getCardResponse();
    }

    saveTransactionAuditData(cardRequest, cardResponse);

    return cardResponse;
}

void CardTransactionManagerAdapter::finalizeSvCommandIfNeeded()
{
    if (mSvLastModifyingCommand == nullptr) {
        return;
    }

    std::vector<uint8_t> svComplementaryData;

    if (mSvLastModifyingCommand->getCommandRef() == CalypsoCardCommand::SV_RELOAD) {

        /* SV RELOAD: get the security data from the SAM. */
        auto svCommand = std::dynamic_pointer_cast<CmdCardSvReload>(mSvLastModifyingCommand);

        svComplementaryData = processSamSvPrepareLoad(mCard->getSvGetHeader(),
                                                      mCard->getSvGetData(),
                                                      svCommand);

        /* Finalize the SV command with the data provided by the SAM. */
        svCommand->finalizeCommand(svComplementaryData);

    } else {

        /* SV DEBIT/UNDEBIT: get the security data from the SAM. */
        auto svCommand = std::dynamic_pointer_cast<CmdCardSvDebitOrUndebit>(mSvLastModifyingCommand);

        svComplementaryData = processSamSvPrepareDebitOrUndebit(
                                  svCommand->getCommandRef() == CalypsoCardCommand::SV_DEBIT,
                                  mCard->getSvGetHeader(),
                                  mCard->getSvGetData(),
                                  svCommand);

        /* Finalize the SV command with the data provided by the SAM. */
        svCommand->finalizeCommand(svComplementaryData);
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::processSamSvPrepareLoad(
    const std::vector<uint8_t>& svGetHeader,
    const std::vector<uint8_t>& svGetData,
    const std::shared_ptr<CmdCardSvReload> cmdCardSvReload)
{
    const std::shared_ptr<CmdSamSvPrepareLoad> cmdSamSvPrepareLoad =
        mControlSamTransactionManager->prepareSvPrepareLoad(svGetHeader, svGetData, cmdCardSvReload);
    mControlSamTransactionManager->processCommands();
    const std::vector<uint8_t> prepareOperationData =
        cmdSamSvPrepareLoad->getApduResponse()->getDataOut();

    return computeOperationComplementaryData(prepareOperationData);
}

const std::vector<uint8_t> CardTransactionManagerAdapter::processSamSvPrepareDebitOrUndebit(
    const bool isDebitCommand,
    const std::vector<uint8_t> svGetHeader,
    const std::vector<uint8_t> svGetData,
    const std::shared_ptr<CmdCardSvDebitOrUndebit> cmdCardSvDebitOrUndebit)
{
    const std::shared_ptr<CmdSamSvPrepareDebitOrUndebit> cmdSamSvPrepareDebitOrUndebit =
        mControlSamTransactionManager->prepareSvPrepareDebitOrUndebit(isDebitCommand,
                                                                      svGetHeader,
                                                                      svGetData,
                                                                      cmdCardSvDebitOrUndebit);
    mControlSamTransactionManager->processCommands();
    const std::vector<uint8_t> prepareOperationData =
        cmdSamSvPrepareDebitOrUndebit->getApduResponse()->getDataOut();

    return computeOperationComplementaryData(prepareOperationData);
}

const std::vector<uint8_t> CardTransactionManagerAdapter::computeOperationComplementaryData(
    const std::vector<uint8_t>& prepareOperationData)
{
    const std::vector<uint8_t>& samSerialNumber =
        mSecuritySetting->getControlSam()->getSerialNumber();
    std::vector<uint8_t> operationComplementaryData(samSerialNumber.size() +
                                                    prepareOperationData.size());

    System::arraycopy(samSerialNumber, 0, operationComplementaryData, 0, samSerialNumber.size());
    System::arraycopy(prepareOperationData,
                      0,
                      operationComplementaryData,
                      samSerialNumber.size(),
                      prepareOperationData.size());

    return operationComplementaryData;
}

void CardTransactionManagerAdapter::processSamSvCheck(const std::vector<uint8_t>& svOperationData)
{
    mControlSamTransactionManager->prepareSvCheck(svOperationData);

    try {
        mControlSamTransactionManager->processCommands();
    } catch (const ReaderIOException& e) {
        throw CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV,
                                                  std::make_shared<ReaderIOException>(e));
    } catch (const SamIOException& e) {
        throw CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV,
                                                  std::make_shared<SamIOException>(e));
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::processSamGetChallenge()
{
    const std::shared_ptr<CmdSamGetChallenge> cmdSamGetChallenge =
        mControlSamTransactionManager->prepareGetChallenge();
    mControlSamTransactionManager->processCommands();
    const std::vector<uint8_t> samChallenge = cmdSamGetChallenge->getChallenge();

    mLogger->debug("SAM_CHALLENGE=%\n", HexUtil::toHex(samChallenge));

    return samChallenge;
}

const std::vector<uint8_t> CardTransactionManagerAdapter::processSamSessionClosing()
{
    const std::shared_ptr<CmdSamDigestClose> cmdSamDigestClose =
        mControlSamTransactionManager->prepareSessionClosing();
    mControlSamTransactionManager->processCommands();
    const std::vector<uint8_t> terminalSignature = cmdSamDigestClose->getSignature();

    mLogger->debug("SAM_SIGNATURE=%\n", HexUtil::toHex(terminalSignature));

    return terminalSignature;
}

void CardTransactionManagerAdapter::processSamDigestAuthenticate(
    const std::vector<uint8_t>& cardSignature)
{
    mControlSamTransactionManager->prepareDigestAuthenticate(cardSignature);

    try {
        mControlSamTransactionManager->processCommands();
    } catch (const ReaderIOException& e) {
        throw CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE,
                                                  std::make_shared<ReaderIOException>(e));
    } catch (const SamIOException& e) {
        throw CardSignatureNotVerifiableException(MSG_CARD_SIGNATURE_NOT_VERIFIABLE,
                                                  std::make_shared<SamIOException>(e));
    }
}

void CardTransactionManagerAdapter::checkSession()
{
    if (!mIsSessionOpen) {
        throw IllegalStateException("No session is open");
    }
}

void CardTransactionManagerAdapter::checkNoSession()
{
    if (mIsSessionOpen) {
        throw IllegalStateException("Session is open");
    }
}

int CardTransactionManagerAdapter::computeCommandSessionBufferSize(
    std::shared_ptr<AbstractCardCommand> command)
{
    return mCard->isModificationsCounterInBytes() ?
               static_cast<int>(command->getApduRequest()->getApdu().size()) +
                   SESSION_BUFFER_CMD_ADDITIONAL_COST -
                   APDU_HEADER_LENGTH :
               1;
}


void CardTransactionManagerAdapter::resetModificationsBufferCounter()
{
    mLogger->trace("Modifications buffer counter reset: PREVIOUSVALUE = %, NEWVALUE = %\n",
                   mModificationsCounter,
                   mCard->getModificationsCounter());

    mModificationsCounter = mCard->getModificationsCounter();
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReleaseCardChannel()
{
    mChannelControl = ChannelControl::CLOSE_AFTER;

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSelectFile(
    const std::vector<uint8_t>& lid)
{
    Assert::getInstance().isEqual(lid.size(), 2, "lid length");

    return prepareSelectFile(static_cast<uint16_t>(ByteArrayUtil::extractInt(lid, 0, 2, false)));
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSelectFile(const uint16_t lid)
{
    mCardCommands.push_back(std::make_shared<CmdCardSelectFile>(mCard->getCardClass(),
                                                                mCard->getProductType(),
                                                                lid));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSelectFile(
    const SelectFileControl selectFileControl)
{
    /* Create the command and add it to the list of commands */
    mCardCommands.push_back(std::make_shared<CmdCardSelectFile>(mCard->getCardClass(),
                                                                selectFileControl));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareGetData(const GetDataTag tag)
{
    /* Create the command and add it to the list of commands */
    switch (tag) {
    case GetDataTag::FCI_FOR_CURRENT_DF:
        mCardCommands.push_back(std::make_shared<CmdCardGetDataFci>(mCard->getCardClass()));
        break;
    case GetDataTag::FCP_FOR_CURRENT_FILE:
        mCardCommands.push_back(std::make_shared<CmdCardGetDataFcp>(mCard->getCardClass()));
        break;
    case GetDataTag::EF_LIST:
        mCardCommands.push_back(std::make_shared<CmdCardGetDataEfList>(mCard->getCardClass()));
        break;
    case GetDataTag::TRACEABILITY_INFORMATION:
        mCardCommands.push_back(
            std::make_shared<CmdCardGetDataTraceabilityInformation>(mCard->getCardClass()));
        break;
    default:
        std::stringstream ss;
        ss << tag;
        throw UnsupportedOperationException("Unsupported Get Data tag: " + ss.str());
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecordFile(
    const uint8_t sfi, const uint8_t recordNumber)
{
    return prepareReadRecord(sfi, recordNumber);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecordFile(
    const uint8_t sfi,
    const uint8_t firstRecordNumber,
    const uint8_t numberOfRecords,
    const uint8_t recordSize)
{
    return prepareReadRecords(sfi,
                              firstRecordNumber,
                              firstRecordNumber + numberOfRecords - 1,
                              recordSize);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadCounterFile(
    const uint8_t sfi, const uint8_t countersNumber)
{
    return prepareReadCounter(sfi, countersNumber);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecord(
    const uint8_t sfi, const uint8_t recordNumber)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(recordNumber,
                                    CalypsoCardConstant::NB_REC_MIN,
                                    CalypsoCardConstant::NB_REC_MAX,
                                    RECORD_NUMBER);

    if (mIsSessionOpen &&
       !std::dynamic_pointer_cast<CardReader>(mCardReader)->isContactless()) {
        throw IllegalStateException("Explicit record size is expected inside a secure session in " \
                                    "contact mode.");
    }

    auto cmdCardReadRecords =
        std::make_shared<CmdCardReadRecords>(mCard->getCardClass(),
                                             sfi,
                                             recordNumber,
                                             CmdCardReadRecords::ReadMode::ONE_RECORD,
                                             static_cast<uint8_t>(0));
    mCardCommands.push_back(cmdCardReadRecords);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecords(
    const uint8_t sfi,
    const uint8_t fromRecordNumber,
    const uint8_t toRecordNumber,
    const uint8_t recordSize)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                          .isInRange(fromRecordNumber,
                                     CalypsoCardConstant::NB_REC_MIN,
                                     CalypsoCardConstant::NB_REC_MAX,
                                     "fromRecordNumber")
                          .isInRange(toRecordNumber,
                                     fromRecordNumber,
                                     CalypsoCardConstant::NB_REC_MAX,
                                     "toRecordNumber");

    if (toRecordNumber == fromRecordNumber) {
        /* Create the command and add it to the list of commands */
        mCardCommands.push_back(
            std::make_shared<CmdCardReadRecords>(mCard->getCardClass(),
                                                 sfi,
                                                 fromRecordNumber,
                                                 CmdCardReadRecords::ReadMode::ONE_RECORD,
                                                 recordSize));
    } else {
        /*
         * Manages the reading of multiple records taking into account the transmission capacity
         * of the card and the response format (2 extra bytes).
         * Multiple APDUs can be generated depending on record size and transmission capacity.
         */
        const CalypsoCardClass cardClass = mCard->getCardClass();
        const uint8_t nbBytesPerRecord = recordSize + 2;
        const uint8_t nbRecordsPerApdu =
            static_cast<uint8_t>(mCard->getPayloadCapacity() / nbBytesPerRecord);
        const uint8_t dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

        uint8_t currentRecordNumber = fromRecordNumber;
        uint8_t nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
        uint8_t currentLength;

        while (currentRecordNumber < toRecordNumber) {
            currentLength = nbRecordsRemainingToRead <= nbRecordsPerApdu ?
                                nbRecordsRemainingToRead * nbBytesPerRecord :
                                dataSizeMaxPerApdu;

            mCardCommands.push_back(
                std::make_shared<CmdCardReadRecords>(cardClass,
                                                     sfi,
                                                     currentRecordNumber,
                                                     CmdCardReadRecords::ReadMode::MULTIPLE_RECORD,
                                                     currentLength));

            currentRecordNumber += (currentLength / nbBytesPerRecord);
            nbRecordsRemainingToRead -= (currentLength / nbBytesPerRecord);
        }

        /* Optimization: prepare a read "one record" if possible for last iteration.*/
        if (currentRecordNumber == toRecordNumber) {
            mCardCommands.push_back(
                std::make_shared<CmdCardReadRecords>(cardClass,
                                                     sfi,
                                                     currentRecordNumber,
                                                     CmdCardReadRecords::ReadMode::ONE_RECORD,
                                                     recordSize));
        }
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecordsPartially(
    const uint8_t sfi,
    const uint8_t fromRecordNumber,
    const uint8_t toRecordNumber,
    const uint8_t offset,
    const uint8_t nbBytesToRead)
{
    if (mCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3 &&
        mCard->getProductType() != CalypsoCard::ProductType::LIGHT) {
        throw UnsupportedOperationException("The 'Read Record Multiple' command is not available "\
                                            "for this card.");
    }

    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                          .isInRange(fromRecordNumber,
                                     CalypsoCardConstant::NB_REC_MIN,
                                     CalypsoCardConstant::NB_REC_MAX,
                                     "fromRecordNumber")
                        .isInRange(toRecordNumber,
                                   fromRecordNumber,
                                   CalypsoCardConstant::NB_REC_MAX,
                                   "toRecordNumber")
                        .isInRange(offset,
                                   CalypsoCardConstant::OFFSET_MIN,
                                   CalypsoCardConstant::OFFSET_MAX,
                                   OFFSET)
                        .isInRange(nbBytesToRead,
                                   CalypsoCardConstant::DATA_LENGTH_MIN,
                                   CalypsoCardConstant::DATA_LENGTH_MAX - offset,
                                   "nbBytesToRead");

    const CalypsoCardClass cardClass = mCard->getCardClass();
    const uint8_t nbRecordsPerApdu =
        static_cast<uint8_t>(mCard->getPayloadCapacity() / nbBytesToRead);

    uint8_t currentRecordNumber = fromRecordNumber;

    while (currentRecordNumber <= toRecordNumber) {
        mCardCommands.push_back(
            std::make_shared<CmdCardReadRecordMultiple>(cardClass,
                                                        sfi,
                                                        currentRecordNumber,
                                                        offset,
                                                        nbBytesToRead));
        currentRecordNumber += nbRecordsPerApdu;
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadBinary(
    const uint8_t sfi, const uint8_t offset, const uint8_t nbBytesToRead)
{
    if (mCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3) {
        throw UnsupportedOperationException("The 'Read Binary' command is not available for this " \
                                            "card.");
    }

    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(offset,
                                    CalypsoCardConstant::OFFSET_MIN,
                                    CalypsoCardConstant::OFFSET_BINARY_MAX,
                                    OFFSET)
                         .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");

    /* C++: no need to check offset > 255, forced by value type */
    if (sfi > 0) {
        /* Tips to select the file: add a "Read Binary" command (read one byte at offset 0). */
        mCardCommands.push_back(
            std::make_shared<CmdCardReadBinary>(mCard->getCardClass(),
                                                sfi,
                                                static_cast<uint8_t>(0),
                                                static_cast<uint8_t>(1)));
    }

    const uint8_t payloadCapacity = mCard->getPayloadCapacity();
    const CalypsoCardClass cardClass = mCard->getCardClass();

    uint8_t currentLength;
    uint8_t currentOffset = offset;
    uint8_t nbBytesRemainingToRead = nbBytesToRead;

    do {
        currentLength = std::min(nbBytesRemainingToRead, payloadCapacity);
        mCardCommands.push_back(std::make_shared<CmdCardReadBinary>(cardClass,
                                                                    sfi,
                                                                    currentOffset,
                                                                    currentLength));

        currentOffset += currentLength;
        nbBytesRemainingToRead -= currentLength;
    } while (nbBytesRemainingToRead > 0);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadCounter(
    const uint8_t sfi, const uint8_t nbCountersToRead)
{
    return prepareReadRecords(sfi, 1, 1, nbCountersToRead * 3);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSearchRecords(
    const std::shared_ptr<SearchCommandData> data)
{
    if (mCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3) {
        throw UnsupportedOperationException("The 'Search Record Multiple' command is not " \
                                            "available for this card.");
    }

    auto dataAdapter = std::dynamic_pointer_cast<SearchCommandDataAdapter>(data);
    if (!dataAdapter) {
        throw IllegalArgumentException("The provided data must be an instance of " \
                                       "'SearchCommandDataAdapter'");
    }

    Assert::getInstance().notNull(dataAdapter, "data")
                         .isInRange(dataAdapter->getSfi(),
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(dataAdapter->getRecordNumber(),
                                    CalypsoCardConstant::NB_REC_MIN,
                                    CalypsoCardConstant::NB_REC_MAX,
                                    "startAtRecord")
                         .isInRange(dataAdapter->getOffset(),
                                    CalypsoCardConstant::OFFSET_MIN,
                                    CalypsoCardConstant::OFFSET_MAX,
                                    OFFSET)
                         .isInRange(dataAdapter->getSearchData().size(),
                                    CalypsoCardConstant::DATA_LENGTH_MIN,
                                    CalypsoCardConstant::DATA_LENGTH_MAX - dataAdapter->getOffset(),
                                    "searchData");
    if (!dataAdapter->getMask().empty()) {
        Assert::getInstance().isInRange(dataAdapter->getMask().size(),
                                        CalypsoCardConstant::DATA_LENGTH_MIN,
                                        dataAdapter->getSearchData().size(),
                                        "mask");
    }

    mCardCommands.push_back(std::make_shared<CmdCardSearchRecordMultiple>(mCard->getCardClass(),
                                                                          dataAdapter));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareAppendRecord(
    const uint8_t sfi, const std::vector<uint8_t>& recordData)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi");

    /* Create the command and add it to the list of commands */
    mCardCommands.push_back(std::make_shared<CmdCardAppendRecord>(mCard->getCardClass(),
                                                                  sfi,
                                                                  recordData));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareUpdateRecord(
    const uint8_t sfi,
    const uint8_t recordNumber,
    const std::vector<uint8_t>& recordData)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(recordNumber,
                                    CalypsoCardConstant::NB_REC_MIN,
                                    CalypsoCardConstant::NB_REC_MAX,
                                    RECORD_NUMBER);

    /* Create the command and add it to the list of commands */
    mCardCommands.push_back(std::make_shared<CmdCardUpdateRecord>(mCard->getCardClass(),
                                                                  sfi,
                                                                  recordNumber,
                                                                  recordData));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareWriteRecord(
    const uint8_t sfi,
    const uint8_t recordNumber,
    const std::vector<uint8_t>& recordData)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                          .isInRange(recordNumber,
                                     CalypsoCardConstant::NB_REC_MIN,
                                     CalypsoCardConstant::NB_REC_MAX,
                                     RECORD_NUMBER);

    /* Create the command and add it to the list of commands */
    mCardCommands.push_back(std::make_shared<CmdCardWriteRecord>(mCard->getCardClass(),
                                                                 sfi,
                                                                 recordNumber,
                                                                 recordData));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareUpdateBinary(
    const uint8_t sfi,
    const uint8_t offset,
    const std::vector<uint8_t>& data)
{
    return prepareUpdateOrWriteBinary(true, sfi, offset, data);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareWriteBinary(
    const uint8_t sfi,
    const uint8_t offset,
    const std::vector<uint8_t>& data)
{
    return prepareUpdateOrWriteBinary(false, sfi, offset, data);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareUpdateOrWriteBinary(
    const bool isUpdateCommand,
    const uint8_t sfi,
    const uint8_t offset,
    const std::vector<uint8_t>& data)
{
    if (mCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3) {
        throw UnsupportedOperationException("The 'Update/Write Binary' command is not available " \
                                            "for this card.");
    }

    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(offset,
                                    CalypsoCardConstant::OFFSET_MIN,
                                    CalypsoCardConstant::OFFSET_BINARY_MAX,
                                    OFFSET)
                         .notEmpty(data, "data");

    /* C++: no need to check offset > 255, forced by value type */
    if (sfi > 0) {
        /* Tips to select the file: add a "Read Binary" command (read one byte at offset 0) */
        mCardCommands.push_back(
            std::make_shared<CmdCardReadBinary>(mCard->getCardClass(),
                                                sfi,
                                                static_cast<uint8_t>(0),
                                                static_cast<uint8_t>(1)));
    }

    const uint8_t dataLength = static_cast<uint8_t>(data.size());
    const uint8_t payloadCapacity = mCard->getPayloadCapacity();
    const CalypsoCardClass cardClass = mCard->getCardClass();

    uint8_t currentLength;
    uint8_t currentOffset = offset;
    uint8_t currentIndex = 0;

    do {
        currentLength = static_cast<uint8_t>(
                            std::min(static_cast<int>(dataLength - currentIndex),
                                     static_cast<int>(payloadCapacity)));

        mCardCommands.push_back(
            std::make_shared<CmdCardUpdateOrWriteBinary>(
                isUpdateCommand,
                cardClass,
                sfi,
                currentOffset,
                Arrays::copyOfRange(data, currentIndex, currentIndex + currentLength)));

        currentOffset += currentLength;
        currentIndex += currentLength;
    } while (currentIndex < dataLength);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareIncreaseOrDecreaseCounter(
    const bool isDecreaseCommand,
    const uint8_t sfi,
    const uint8_t counterNumber,
    const int incDecValue)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(counterNumber,
                                    CalypsoCardConstant::NB_CNT_MIN,
                                    CalypsoCardConstant::NB_CNT_MAX,
                                    "counterNumber")
                         .isInRange(incDecValue,
                                    CalypsoCardConstant::CNT_VALUE_MIN,
                                    CalypsoCardConstant::CNT_VALUE_MAX,
                                    "incDecValue");

    /* Create the command and add it to the list of commands */
    mCardCommands.push_back(std::make_shared<CmdCardIncreaseOrDecrease>(isDecreaseCommand,
                                                                        mCard->getCardClass(),
                                                                        sfi,
                                                                        counterNumber,
                                                                        incDecValue));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareIncreaseCounter(
    const uint8_t sfi, const uint8_t counterNumber, const int incValue)
{
    return prepareIncreaseOrDecreaseCounter(false, sfi, counterNumber, incValue);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareDecreaseCounter(
    const uint8_t sfi, const uint8_t counterNumber, const int decValue)
{
    return prepareIncreaseOrDecreaseCounter(true, sfi, counterNumber, decValue);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareIncreaseCounters(
    const uint8_t sfi,
    const std::map<const int, const int>& counterNumberToIncValueMap)
{
    return prepareIncreaseOrDecreaseCounters(false, sfi, counterNumberToIncValueMap);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareDecreaseCounters(
    const uint8_t sfi,
    const std::map<const int, const int>& counterNumberToDecValueMap)
{
    return prepareIncreaseOrDecreaseCounters(true, sfi, counterNumberToDecValueMap);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareCheckPinStatus()
{
    if (!mCard->isPinFeatureAvailable()) {
        throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
    }

    /* Create the command and add it to the list of commands */
    mCardCommands.push_back(std::make_shared<CmdCardVerifyPin>(mCard->getCardClass()));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvGet(const SvOperation svOperation,
                                                                    const SvAction svAction)
{
    if (!mCard->isSvFeatureAvailable()) {
        throw UnsupportedOperationException("Stored Value is not available for this card.");
    }

    /* CL-SV-CMDMODE.1 */
    std::shared_ptr<CalypsoSam> calypsoSam = mSecuritySetting->getControlSam();
    const bool useExtendedMode = mCard->isExtendedModeSupported() &&
                                 (calypsoSam == nullptr ||
                                  calypsoSam->getProductType() == CalypsoSam::ProductType::SAM_C1 ||
                                  calypsoSam->getProductType() == CalypsoSam::ProductType::HSM_C1);

    if (mSecuritySetting->isSvLoadAndDebitLogEnabled() && !useExtendedMode) {

        /*
         * @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
         * for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
         * CL-SV-GETNUMBER.1
         */
        const SvOperation operation1 = SvOperation::RELOAD == svOperation ? SvOperation::DEBIT :
                                                                            SvOperation::RELOAD;
        addStoredValueCommand(std::make_shared<CmdCardSvGet>(mCard->getCardClass(),
                                                             operation1,
                                                             false),
                              operation1);
    }

    addStoredValueCommand(std::make_shared<CmdCardSvGet>(mCard->getCardClass(),
                                                         svOperation,
                                                         useExtendedMode),
                          svOperation);

    mSvAction = svAction;

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvReload(
    const int amount,
    const std::vector<uint8_t>& date,
    const std::vector<uint8_t>& time,
    const std::vector<uint8_t>& free)
{
    checkSvInsideSession();

    /* Create the initial command with the application data */
    auto svReloadCmdBuild = std::make_shared<CmdCardSvReload>(mCard->getCardClass(),
                                                              amount,
                                                              mCard->getSvKvc(),
                                                              date,
                                                              time,
                                                              free,
                                                              isExtendedModeAllowed());

    /* Create and keep the CalypsoCardCommand */
    addStoredValueCommand(svReloadCmdBuild, SvOperation::RELOAD);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvReload(const int amount)
{
    const std::vector<uint8_t> zero = {0x00, 0x00};

    prepareSvReload(amount, zero, zero, zero);

    return *this;
}

void CardTransactionManagerAdapter::checkSvInsideSession()
{
    /* CL-SV-1PCSS.1 */
    if (mIsSessionOpen) {
        if (!mIsSvOperationInsideSession) {
            mIsSvOperationInsideSession = true;
        } else {
            throw IllegalStateException("Only one SV operation is allowed per Secure Session.");
        }
    }
}

bool CardTransactionManagerAdapter::isExtendedModeAllowed() const
{
    std::shared_ptr<CalypsoSam> calypsoSam = mSecuritySetting->getControlSam();

    return mCard->isExtendedModeSupported() &&
           (calypsoSam->getProductType() == CalypsoSam::ProductType::SAM_C1 ||
            calypsoSam->getProductType() == CalypsoSam::ProductType::HSM_C1);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvDebit(
    const int amount,
    const std::vector<uint8_t>& date,
    const std::vector<uint8_t>& time)
{
    checkSvInsideSession();

    if (mSvAction == SvAction::DO &&
        !mSecuritySetting->isSvNegativeBalanceAuthorized() &&
        (mCard->getSvBalance() - amount) < 0) {
        throw IllegalStateException("Negative balances not allowed.");
    }

    /* Create the initial command with the application data */
    auto command = std::make_shared<CmdCardSvDebitOrUndebit>(mSvAction == SvAction::DO,
                                                             mCard->getCardClass(),
                                                             amount,
                                                             mCard->getSvKvc(),
                                                             date,
                                                             time,
                                                             isExtendedModeAllowed());

    /* Create and keep the CalypsoCardCommand */
    addStoredValueCommand(command, SvOperation::DEBIT);

    return *this;
  }

CardTransactionManager& CardTransactionManagerAdapter::prepareSvDebit(const int amount)
{
    const std::vector<uint8_t> zero = {0x00, 0x00};

    prepareSvDebit(amount, zero, zero);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvReadAllLogs()
{
    if (!mCard->isSvFeatureAvailable()) {
        throw UnsupportedOperationException("Stored Value is not available for this card.");
    }

    if (mCard->getApplicationSubtype() !=
        CalypsoCardConstant::STORED_VALUE_FILE_STRUCTURE_ID) {
        throw UnsupportedOperationException("The currently selected application is not an SV " \
                                            "application.");
    }

    /* Reset SV data in CalypsoCard if any */
    const std::vector<uint8_t> dummy;
    mCard->setSvData(0, dummy, dummy, 0, 0, nullptr, nullptr);
    prepareReadRecords(CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI,
                       1,
                       CalypsoCardConstant::SV_RELOAD_LOG_FILE_NB_REC,
                       CalypsoCardConstant::SV_LOG_FILE_REC_LENGTH);
    prepareReadRecords(CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI,
                       1,
                       CalypsoCardConstant::SV_DEBIT_LOG_FILE_NB_REC,
                       CalypsoCardConstant::SV_LOG_FILE_REC_LENGTH);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareInvalidate()
{
    if (mCard->isDfInvalidated()) {
        throw IllegalStateException("This card is already invalidated.");
    }

    mCardCommands.push_back(std::make_shared<CmdCardInvalidate>(mCard->getCardClass()));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareRehabilitate()
{
    if (!mCard->isDfInvalidated()) {
        throw IllegalStateException("This card is not invalidated.");
    }

    mCardCommands.push_back(std::make_shared<CmdCardRehabilitate>(mCard->getCardClass()));

    return *this;
}

void CardTransactionManagerAdapter::addStoredValueCommand(
    const std::shared_ptr<AbstractCardCommand> command, const SvOperation svOperation)
{
    /* Check the logic of the SV command sequencing */
    if (command->getCommandRef() == CalypsoCardCommand::SV_GET) {
        mSvOperation = svOperation;

    } else if (command->getCommandRef() == CalypsoCardCommand::SV_RELOAD ||
               command->getCommandRef() == CalypsoCardCommand::SV_DEBIT ||
               command->getCommandRef() == CalypsoCardCommand::SV_UNDEBIT) {
        /*
         * CL-SV-GETDEBIT.1
         * CL-SV-GETRLOAD.1
         */
        if (!mCardCommands.empty()) {
            throw IllegalStateException("This SV command can only be placed in the first position" \
                                        " in the list of prepared commands");
        }

        if (mSvLastCommandRef != CalypsoCardCommand::SV_GET) {
            throw IllegalStateException("This SV command must follow an SV Get command");
        }

        /* Here, we expect the command and the SV operation to be consistent */
        if (svOperation != mSvOperation) {
            mLogger->error("Sv operation = %, current command = %\n", mSvOperation, svOperation);
            throw IllegalStateException("Inconsistent SV operation.");
        }

        mIsSvOperationComplete = true;
        mSvLastModifyingCommand = command;

    } else {
        throw IllegalStateException("An SV command is expected.");
    }

    mSvLastCommandRef = command->getCommandRef();
    mCardCommands.push_back(command);
}

void CardTransactionManagerAdapter::notifyCommandsProcessed()
{
    mCardCommands.clear();
    mSvLastModifyingCommand = nullptr;
}

bool CardTransactionManagerAdapter::isSvOperationCompleteOneTime()
{
    const bool flag = mIsSvOperationComplete;
    mIsSvOperationComplete = false;

    return flag;
}

/* APDU RESPONSE ADAPTER ------------------------------------------------------------------------ */

CardTransactionManagerAdapter::ApduResponseAdapter::ApduResponseAdapter(
  const std::vector<uint8_t>& apdu)
: mApdu(apdu),
  mStatusWord(((apdu[apdu.size() - 2] & 0x000000FF) << 8) + (apdu[apdu.size() - 1] & 0x000000FF)) {}

const std::vector<uint8_t>& CardTransactionManagerAdapter::ApduResponseAdapter::getApdu() const
{
    return mApdu;
}

const std::vector<uint8_t> CardTransactionManagerAdapter::ApduResponseAdapter::getDataOut() const
{
    return Arrays::copyOfRange(mApdu, 0, mApdu.size() - 2);
}

int CardTransactionManagerAdapter::ApduResponseAdapter::getStatusWord() const
{
    return mStatusWord;
}

std::ostream& operator<<(std::ostream& os, const CardTransactionManagerAdapter::ApduResponseAdapter& ara)
{
    os << "APDU_RESPONSE_ADAPTER: {"
       << "APDU: " << ara.getApdu() << ", "
       << "STATUS_WORD: " << ara.getStatusWord()
       << "}";

    return os;
}


std::ostream& operator<<(std::ostream& os, const std::shared_ptr<CardTransactionManagerAdapter::ApduResponseAdapter> ara)
{
    if (ara == nullptr) {
        os << "APDU_RESPONSE_ADAPTER: null";
    } else {
        os << *ara;
    }

    return os;
}

}
}
}
