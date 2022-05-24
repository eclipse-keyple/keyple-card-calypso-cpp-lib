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

#include "CardTransactionManagerAdapter.h"

#include <algorithm>
#include <sstream>

/* Calypsonet Terminal Calypso */
#include "AtomicTransactionException.h"
#include "CardAnomalyException.h"
#include "CardCloseSecureSessionException.h"
#include "CardIOException.h"
#include "DesynchronizedExchangesException.h"
#include "SamAnomalyException.h"
#include "SamAnomalyException.h"
#include "SamIOException.h"
#include "SessionAuthenticationException.h"
#include "SvAuthenticationException.h"
#include "UnauthorizedKeyException.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"
#include "CardBrokenCommunicationException.h"
#include "CardResponseApi.h"
#include "ReaderBrokenCommunicationException.h"
#include "UnexpectedStatusWordException.h"

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
#include "IllegalStateException.h"
#include "KeypleAssert.h"
#include "KeypleStd.h"
#include "MapUtils.h"
#include "UnsupportedOperationException.h"
#include "CmdCardRatificationBuilder.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace keyple::card::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

/* CARD TRANSACTION MANAGER ADAPTER ------------------------------------------------------------- */

const std::string CardTransactionManagerAdapter::CARD_READER_COMMUNICATION_ERROR =
    "A communication error with the card reader occurred while ";
const std::string CardTransactionManagerAdapter::CARD_COMMUNICATION_ERROR =
    "A communication error with the card occurred while ";
const std::string CardTransactionManagerAdapter::CARD_COMMAND_ERROR =
    "A card command error occurred while ";
const std::string CardTransactionManagerAdapter::SAM_READER_COMMUNICATION_ERROR =
    "A communication error with the SAM reader occurred while ";
const std::string CardTransactionManagerAdapter::SAM_COMMUNICATION_ERROR =
    "A communication error with the SAM occurred while ";
const std::string CardTransactionManagerAdapter::SAM_COMMAND_ERROR =
    "A SAM command error occurred while ";
const std::string CardTransactionManagerAdapter::PIN_NOT_AVAILABLE_ERROR =
    "PIN is not available for this card.";
const std::string CardTransactionManagerAdapter::GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR =
    "generating of the PIN ciphered data.";
const std::string CardTransactionManagerAdapter::GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR =
    "generating of the key ciphered data.";
const std::string CardTransactionManagerAdapter::TRANSMITTING_COMMANDS =
    "transmitting commands.";
const std::string CardTransactionManagerAdapter::CHECKING_THE_SV_OPERATION =
    "checking the SV operation.";
const std::string CardTransactionManagerAdapter::UNEXPECTED_EXCEPTION =
    "An unexpected exception was raised.";
const std::string CardTransactionManagerAdapter::RECORD_NUMBER = "recordNumber";

const int CardTransactionManagerAdapter::SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;
const int CardTransactionManagerAdapter::APDU_HEADER_LENGTH = 5;

const std::string CardTransactionManagerAdapter::OFFSET = "offset";

const std::shared_ptr<ApduResponseApi> CardTransactionManagerAdapter::RESPONSE_OK =
    std::make_shared<ApduResponseAdapter>(std::vector<uint8_t>({0x90, 0x00}));
const std::shared_ptr<ApduResponseApi> CardTransactionManagerAdapter::RESPONSE_OK_POSTPONED =
    std::make_shared<ApduResponseAdapter>(std::vector<uint8_t>({0x62, 0x00}));

CardTransactionManagerAdapter::CardTransactionManagerAdapter(
  const std::shared_ptr<CardReader> cardReader,
  const std::shared_ptr<CalypsoCard> calypsoCard,
  const std::shared_ptr<CardSecuritySetting> cardSecuritySetting)
: mCardReader(std::dynamic_pointer_cast<ProxyReaderApi>(cardReader)),
  mCardSecuritySettings(cardSecuritySetting),
  mSamCommandProcessor(cardSecuritySetting ?
                       std::make_shared<SamCommandProcessor>(calypsoCard, cardSecuritySetting) :
                       nullptr),
  mCalypsoCard(std::dynamic_pointer_cast<CalypsoCardAdapter>(calypsoCard)),
  mSessionState(SessionState::SESSION_UNINITIALIZED),
  mModificationsCounter(mCalypsoCard->getModificationsCounter()),
  mCardCommandManager(std::make_shared<CardCommandManager>()),
  mChannelControl(ChannelControl::KEEP_OPEN) {}

CardTransactionManagerAdapter::CardTransactionManagerAdapter(
  const std::shared_ptr<CardReader> cardReader,
  const std::shared_ptr<CalypsoCard> calypsoCard)
: CardTransactionManagerAdapter(cardReader, calypsoCard, nullptr) {}

const std::shared_ptr<CardReader> CardTransactionManagerAdapter::getCardReader() const
{
    return std::dynamic_pointer_cast<CardReader>(mCardReader);
}

const std::shared_ptr<CalypsoCard> CardTransactionManagerAdapter::getCalypsoCard() const
{
    return mCalypsoCard;
}

const std::shared_ptr<CardSecuritySetting> CardTransactionManagerAdapter::getCardSecuritySetting()
    const
{
    return mCardSecuritySettings;
}

const std::string CardTransactionManagerAdapter::getTransactionAuditData() const
{
    return "";
}

void CardTransactionManagerAdapter::processAtomicOpening(
    const WriteAccessLevel writeAccessLevel,
    std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands)
{
    /* This method should be invoked only if no session was previously open */
    checkSessionNotOpen();

    if (mCardSecuritySettings == nullptr) {
        throw IllegalStateException("No security settings are available.");
    }

    const std::vector<uint8_t> sessionTerminalChallenge = getSessionTerminalChallenge();

    /* Card ApduRequestAdapter List to hold Open Secure Session and other optional commands */
    std::vector<std::shared_ptr<ApduRequestSpi>> cardApduRequests;

    /*
     * The sfi and record number to be read when the open secure session command is executed.
     * The default value is 0 (no record to read) but we will optimize the exchanges if a read
     * record command has been prepared.
     */
    int sfi = 0;
    int recordNumber = 0;

    /*
     * Let's check if we have a read record command at the top of the command list.
     *
     * If so, then the command is withdrawn in favour of its equivalent executed at the same
     * time as the open secure session command.
     */
    if (!cardCommands.empty()) {
        const std::shared_ptr<AbstractCardCommand> cardCommand = cardCommands[0];
        if (cardCommand->getCommandRef() == CalypsoCardCommand::READ_RECORDS &&
            std::dynamic_pointer_cast<CmdCardReadRecords>(cardCommand)->getReadMode() ==
                CmdCardReadRecords::ReadMode::ONE_RECORD) {
            sfi = std::dynamic_pointer_cast<CmdCardReadRecords>(cardCommand)->getSfi();
            recordNumber =
                std::dynamic_pointer_cast<CmdCardReadRecords>(cardCommand)->getFirstRecordNumber();
            cardCommands.erase(cardCommands.begin());
        }
    }

    /* Build the card Open Secure Session command */
    auto cmdCardOpenSession =
        std::make_shared<CmdCardOpenSession>(mCalypsoCard,
                                             static_cast<int>(writeAccessLevel) + 1,
                                             sessionTerminalChallenge,
                                             sfi,
                                             recordNumber);

    /* Add the resulting ApduRequestAdapter to the card ApduRequestAdapter list */
    cardApduRequests.push_back(cmdCardOpenSession->getApduRequest());

    /* Add all optional commands to the card ApduRequestAdapter list */
    Arrays::addAll(cardApduRequests, getApduRequests(cardCommands));

    /*
     * Create a CardRequest from the ApduRequestAdapter list, card AID as Selector, keep channel
     * open
     */
    auto cardRequest = std::make_shared<CardRequestAdapter>(cardApduRequests, false);

    /* Transmit the commands to the card */
    const std::shared_ptr<CardResponseApi> cardResponse = safeTransmit(cardRequest,
                                                                       ChannelControl::KEEP_OPEN);

    /* Retrieve and check the ApduResponses */
    std::vector<std::shared_ptr<ApduResponseApi>> cardApduResponses =
        cardResponse->getApduResponses();

    /* Do some basic checks */
    checkCommandsResponsesSynchronization(cardApduRequests.size(), cardApduResponses.size());

    /*
     * Parse the response to Open Secure Session (the first item of cardApduResponses)
     * The updateCalypsoCard method fills the CalypsoCard object with the command data.
     */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cmdCardOpenSession,
                                                  cardApduResponses[0],
                                                  true);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(std::string(CARD_COMMAND_ERROR) +
                                   "processing the response to open session: " +
                                    e.getCommand().getName(),
                                    std::make_shared<CardCommandException>(e));
    }

    /*
     * Build the Digest Init command from card Open Session the session challenge is needed for the
     * SAM digest computation
     */
    const std::vector<uint8_t> sessionCardChallenge = cmdCardOpenSession->getCardChallenge();

    /* The card KIF */
    const std::shared_ptr<uint8_t> cardKif = cmdCardOpenSession->getSelectedKif();

    /* The card KVC, may be null for card Rev 1.0 */
    const std::shared_ptr<uint8_t> cardKvc = cmdCardOpenSession->getSelectedKvc();

    const std::string logCardKif = cardKif != nullptr ? std::to_string(*cardKif) : "null";
    const std::string logCardKvc = cardKvc != nullptr ? std::to_string(*cardKvc) : "null";
    mLogger->debug("processAtomicOpening => opening: CARDCHALLENGE = %, CARDKIF = %, CARDKVC = %\n",
                   ByteArrayUtil::toHex(sessionCardChallenge),
                   logCardKif,
                   logCardKvc);

    const std::shared_ptr<uint8_t> kvc = mSamCommandProcessor->computeKvc(writeAccessLevel, cardKvc);
    const std::shared_ptr<uint8_t> kif =
        mSamCommandProcessor->computeKif(writeAccessLevel, cardKif, kvc);

    if (!std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
             ->isSessionKeyAuthorized(kif, kvc)) {
        const std::string logKif = kif != nullptr ? std::to_string(*kif) : "null";
        const std::string logKvc = kvc != nullptr ? std::to_string(*kvc) : "null";
        throw UnauthorizedKeyException("Unauthorized key error: KIF = " +
                                       logKif +
                                       ", KVC = " +
                                       logKvc);
    }

    /*
     * Initialize the digest processor. It will store all digest operations (Digest Init, Digest
     * Update) until the session closing. At this moment, all SAM Apdu will be processed at
     * once.
     */
    mSamCommandProcessor->initializeDigester(false,
                                             false,
                                             *kif,
                                             *kvc,
                                             cardApduResponses[0]->getDataOut());

    /*
     * Add all commands data to the digest computation. The first command in the list is the
     * open secure session command. This command is not included in the digest computation, so
     * we skip it and start the loop at index 1.
     */
    if (!cardCommands.empty()) {
        /* Add requests and responses to the digest processor */
        mSamCommandProcessor->pushCardExchangedData(cardApduRequests, cardApduResponses, 1);
    }

    /* Remove Open Secure Session response and create a new CardResponse */
    cardApduResponses.erase(cardApduResponses.begin());

    /* Update CalypsoCard with the received data */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cardCommands,
                                                  cardApduResponses,
                                                  true);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing the response to open session: " +
                                    e.getCommand().getName(),
                                    std::make_shared<CardCommandException>(e));
    }

    mSessionState = SessionState::SESSION_OPEN;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSetCounter(const uint8_t sfi,
                                                                         const int counterNumber,
                                                                         const int newValue)
{
    std::shared_ptr<int> oldValue;

    const std::shared_ptr<ElementaryFile> ef = mCalypsoCard->getFileBySfi(sfi);
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
    if (mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3 &&
        mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_2) {
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

    const int nbCountersPerApdu = mCalypsoCard->getPayloadCapacity() / 4;

    if (static_cast<int>(counterNumberToIncDecValueMap.size()) <= nbCountersPerApdu) {
        /* Create the command and add it to the list of commands */
        const std::map<const int, const int> dummy;
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardIncreaseOrDecreaseMultiple>(
                isDecreaseCommand,
                mCalypsoCard->getCardClass(),
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
                mCardCommandManager->addRegularCommand(
                    std::make_shared<CmdCardIncreaseOrDecreaseMultiple>(
                        isDecreaseCommand,
                        mCalypsoCard->getCardClass(),
                        sfi,
                        map));
                i = 0;
                map.clear();
            }
        }

        if (!map.empty()) {
            mCardCommandManager->addRegularCommand(
                std::make_shared<CmdCardIncreaseOrDecreaseMultiple>(isDecreaseCommand,
                                                                    mCalypsoCard->getCardClass(),
                                                                    sfi,
                                                                    map));
        }
    }

    return *this;
}

const std::vector<std::shared_ptr<ApduRequestSpi>> CardTransactionManagerAdapter::getApduRequests(
    const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    if (!cardCommands.empty()) {
        for (const auto& command : cardCommands) {
            apduRequests.push_back(command->getApduRequest());
        }
    }

    return apduRequests;
}

void CardTransactionManagerAdapter::processAtomicCardCommands(
    const std::vector<std::shared_ptr<AbstractCardCommand>> cardCommands,
    const ChannelControl channelControl)
{
    /* Get the card ApduRequestAdapter List */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests = getApduRequests(cardCommands);

    /*
     * Create a CardRequest from the ApduRequestAdapter list, card AID as Selector, manage the
     * logical channel according to the channelControl
     */
    std::shared_ptr<CardRequestSpi> cardRequest =
        std::make_shared<CardRequestAdapter>(apduRequests, false);

    /* Transmit the commands to the card */
    const std::shared_ptr<CardResponseApi> cardResponse = safeTransmit(cardRequest, channelControl);

    /* Retrieve and check the ApduResponses */
    const std::vector<std::shared_ptr<ApduResponseApi>> cardApduResponses =
        cardResponse->getApduResponses();

    /* Do some basic checks */
    checkCommandsResponsesSynchronization(apduRequests.size(), cardApduResponses.size());

    /*
     * Add all commands data to the digest computation if this method is invoked within a Secure
     * Session.
     */
    if (mSessionState == SessionState::SESSION_OPEN) {
        mSamCommandProcessor->pushCardExchangedData(apduRequests, cardApduResponses, 0);
    }

    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cardCommands,
                                                  cardResponse->getApduResponses(),
                                                  mSessionState == SessionState::SESSION_OPEN);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing responses to card commands: " +
                                   e.getCommand().getName(),
                                   std::make_shared<CardCommandException>(e));
    }
}

void CardTransactionManagerAdapter::processAtomicClosing(
    const std::vector<std::shared_ptr<AbstractCardCommand>>& cardModificationCommands,
    const std::vector<std::shared_ptr<ApduResponseApi>>& cardAnticipatedResponses,
    const bool isRatificationMechanismEnabled,
    const ChannelControl channelControl)
{
    checkSessionOpen();

    /* Get the card ApduRequestAdapter List - for the first card exchange */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests =
        getApduRequests(cardModificationCommands);

    /* Compute "anticipated" Digest Update (for optional cardModificationCommands) */
    if (!cardModificationCommands.empty() && !apduRequests.empty()) {
        checkCommandsResponsesSynchronization(apduRequests.size(), cardAnticipatedResponses.size());

        /* Add all commands data to the digest computation: commands and anticipated responses */
        mSamCommandProcessor->pushCardExchangedData(apduRequests, cardAnticipatedResponses, 0);
    }

    /*
     * All SAM digest operations will now run at once.
     * Get Terminal Signature from the latest response
     */
    const std::vector<uint8_t> sessionTerminalSignature = getSessionTerminalSignature();

    /* Build the card Close Session command. The last one for this session */
    auto cmdCardCloseSession =
        std::make_shared<CmdCardCloseSession>(mCalypsoCard,
                                              !isRatificationMechanismEnabled,
                                              sessionTerminalSignature);

    apduRequests.push_back(cmdCardCloseSession->getApduRequest());

    /* Keep the cardsition of the Close Session command in request list */
    const int closeCommandIndex = apduRequests.size() - 1;

    /* Add the card Ratification command if any */
    bool ratificationCommandAdded;
    if (isRatificationMechanismEnabled &&
        std::dynamic_pointer_cast<CardReader>(mCardReader)->isContactless()) {
        /*
         * CL-RAT-CMD.1
         * CL-RAT-DELAY.1
         * CL-RAT-NXTCLOSE.1
         */
        apduRequests.push_back(
            CmdCardRatificationBuilder::getApduRequest(mCalypsoCard->getCardClass()));
        ratificationCommandAdded = true;
    } else {
        ratificationCommandAdded = false;
    }

    /* Transfer card commands */
    auto cardRequest = std::make_shared<CardRequestAdapter>(apduRequests, false);
    std::shared_ptr<CardResponseApi> cardResponse;

    try {
        cardResponse = mCardReader->transmitCardRequest(cardRequest, channelControl);
    } catch (const CardBrokenCommunicationException& e) {
        cardResponse = e.getCardResponse();

        /*
         * The current exception may have been caused by a communication issue with the card
         * during the ratification command.
         *
         * In this case, we do not stop the process and consider the Secure Session close. We'll
         * check the signature.
         *
         * We should have one response less than requests.
         */
        if (!ratificationCommandAdded ||
            cardResponse == nullptr ||
            cardResponse->getApduResponses().size() != apduRequests.size() - 1) {
            throw CardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS,
                                  std::make_shared<CardBrokenCommunicationException>(e));
        }
    } catch (const ReaderBrokenCommunicationException& e) {
        throw CardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS,
                              std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponses =
        cardResponse->getApduResponses();

    /*
     * Check the commands executed before closing the secure session (only responses to these
     * commands will be taken into account)
     */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cardModificationCommands,
                                                  apduResponses,
                                                  true);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing of responses preceding the close of the session: " +
                                   e.getCommand().getName(),
                                   std::make_shared<CardCommandException>(e));
    }

    /* Check the card's response to Close Secure Session */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cmdCardCloseSession,
                                                  apduResponses[closeCommandIndex],
                                                  true);
    } catch (const CardSecurityDataException& e) {
        throw CardCloseSecureSessionException("Invalid card session",
                                              std::make_shared<CardSecurityDataException>(e));
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing the response to close session: " +
                                   e.getCommand().getName(),
                                   std::make_shared<CardCommandException>(e));
    }

    /*
     * Check the card signature
     * CL-CSS-MACVERIF.1
     */
    checkCardSignature(cmdCardCloseSession->getSignatureLo());

    /*
     * If necessary, we check the status of the SV after the session has been successfully closed.
     * CL-SV-POSTPON.1
     */
    if (mCardCommandManager->isSvOperationCompleteOneTime()) {
        checkSvOperationStatus(cmdCardCloseSession->getPostponedData());
    }

    mSessionState = SessionState::SESSION_CLOSED;
}

void CardTransactionManagerAdapter::processAtomicClosing(
    const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands,
    const bool isRatificationMechanismEnabled,
    const ChannelControl channelControl)
{
    const std::vector<std::shared_ptr<ApduResponseApi>> cardAnticipatedResponses =
        getAnticipatedResponses(cardCommands);

    processAtomicClosing(cardCommands,
                         cardAnticipatedResponses,
                         isRatificationMechanismEnabled,
                         channelControl);
}

int CardTransactionManagerAdapter::getCounterValue(const int sfi, const int counter)
{
    const std::shared_ptr<ElementaryFile> ef = mCalypsoCard->getFileBySfi(sfi);
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
    const int sfi, const std::vector<int>& counters)
{
    const std::shared_ptr<ElementaryFile> ef = mCalypsoCard->getFileBySfi(sfi);
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

const std::shared_ptr<ApduResponseApi> CardTransactionManagerAdapter::createIncreaseDecreaseResponse(
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
    CardTransactionManagerAdapter::createIncreaseDecreaseMultipleResponse(
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
    CardTransactionManagerAdapter::getAnticipatedResponses(
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;

    if (!cardCommands.empty()) {
        for (const auto& command : cardCommands) {
            if (command->getCommandRef() == CalypsoCardCommand::INCREASE ||
                command->getCommandRef() == CalypsoCardCommand::DECREASE) {
                auto incdec = std::dynamic_pointer_cast<CmdCardIncreaseOrDecrease>(command);
                const int sfi = incdec->getSfi();
                const int counter = incdec->getCounterNumber();

                apduResponses.push_back(
                    createIncreaseDecreaseResponse(
                        command->getCommandRef() == CalypsoCardCommand::DECREASE,
                        getCounterValue(sfi, counter),
                        incdec->getIncDecValue()));

            } else if (command->getCommandRef() == CalypsoCardCommand::INCREASE_MULTIPLE ||
                       command->getCommandRef() == CalypsoCardCommand::DECREASE_MULTIPLE) {
                auto incdec = std::dynamic_pointer_cast<CmdCardIncreaseOrDecreaseMultiple>(command);
                const int sfi = incdec->getSfi();
                const std::map<const int, const int> counterNumberToIncDecValueMap =
                    incdec->getCounterNumberToIncDecValueMap();

                apduResponses.push_back(
                    createIncreaseDecreaseMultipleResponse(
                        command->getCommandRef() == CalypsoCardCommand::DECREASE_MULTIPLE,
                        getCounterValues(sfi,
                                         MapUtils::getKeySet(counterNumberToIncDecValueMap)),
                        counterNumberToIncDecValueMap));

            } else if (command->getCommandRef() == CalypsoCardCommand::SV_RELOAD ||
                       command->getCommandRef() == CalypsoCardCommand::SV_DEBIT ||
                       command->getCommandRef() == CalypsoCardCommand::SV_UNDEBIT) {
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
    /* CL-KEY-INDEXPO.1 */
    mCurrentWriteAccessLevel = writeAccessLevel;

    /* Create a sublist of AbstractCardCommand to be sent atomically */
    std::vector<std::shared_ptr<AbstractCardCommand>> cardAtomicCommands;

    std::atomic<int> neededSessionBufferSpace;
    std::atomic<bool> overflow;

    for (const auto& command : mCardCommandManager->getCardCommands()) {
        /*
         * Check if the command is a modifying one and get it status (overflow yes/no,
         * neededSessionBufferSpace). If the command overflows the session buffer in atomic
         * modification mode, an exception is raised.
         */
        if (checkModifyingCommand(command, overflow, neededSessionBufferSpace)) {
            if (overflow) {
                /* Open the session with the current commands */
                processAtomicOpening(mCurrentWriteAccessLevel, cardAtomicCommands);

                /*
                 * Closes the session, resets the modifications buffer counters for the next
                 * round.
                 */
                processAtomicClosing(std::vector<std::shared_ptr<AbstractCardCommand>>(),
                                     false,
                                     ChannelControl::KEEP_OPEN);
                resetModificationsBufferCounter();

                /*
                 *Clear the list and add the command that did not fit in the card modifications
                 * buffer. We also update the usage counter without checking the result.
                 */
                cardAtomicCommands.clear();
                cardAtomicCommands.push_back(command);

                /* Just update modifications buffer usage counter, ignore result (always false) */
                isSessionBufferOverflowed(neededSessionBufferSpace);
            } else {
                /* The command fits in the card modifications buffer, just add it to the list */
                cardAtomicCommands.push_back(command);
            }
        } else {
            /* This command does not affect the card modifications buffer */
            cardAtomicCommands.push_back(command);
        }
    }

    processAtomicOpening(mCurrentWriteAccessLevel, cardAtomicCommands);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    return *this;
}

void CardTransactionManagerAdapter::processCardCommandsOutOfSession(
    const ChannelControl channelControl)
{
    /* Card commands sent outside a Secure Session. No modifications buffer limitation */
    processAtomicCardCommands(mCardCommandManager->getCardCommands(), channelControl);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    /* If an SV transaction was performed, we check the signature returned by the card here  */
    if (mCardCommandManager->isSvOperationCompleteOneTime()) {
        try {
            mSamCommandProcessor->checkSvStatus(mCalypsoCard->getSvOperationSignature());
        } catch (const CalypsoSamSecurityDataException& e) {
            throw SvAuthenticationException("The checking of the SV operation by the SAM has " \
                                            "failed.",
                                            std::make_shared<CalypsoSamSecurityDataException>(e));
        } catch (const CalypsoSamCommandException& e) {
            throw SamAnomalyException(SAM_COMMAND_ERROR +
                                      "checking the SV operation: " +
                                      e.getCommand().getName(),
                                      std::make_shared<CalypsoSamCommandException>(e));
        } catch (const ReaderBrokenCommunicationException& e) {
            throw SvAuthenticationException(
                      SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION,
                      std::make_shared<ReaderBrokenCommunicationException>(e));
        } catch (const CardBrokenCommunicationException& e) {
            throw SvAuthenticationException(SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION,
                                            std::make_shared<CardBrokenCommunicationException>(e));
        }
    }
}

void CardTransactionManagerAdapter::processCardCommandsInSession()
{
    /* A session is open, we have to care about the card modifications buffer */
    std::vector<std::shared_ptr<AbstractCardCommand>> cardAtomicCommands;

    std::atomic<int> neededSessionBufferSpace;
    std::atomic<bool> overflow;

    for (const auto& command : mCardCommandManager->getCardCommands()) {
        /*
         * Check if the command is a modifying one and get it status (overflow yes/no,
         * neededSessionBufferSpace)
         * if the command overflows the session buffer in atomic modification mode, an exception
         * is raised.
         */
        if (checkModifyingCommand(command, overflow, neededSessionBufferSpace)) {
            if (overflow) {
                /*
                * The current command would overflow the modifications buffer in the card. We
                * send the current commands and update the command list. The command Iterator is
                * kept all along the process.
                */
                processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);

                /* Close the session and reset the modifications buffer counters for the next round */
                processAtomicClosing(std::vector<std::shared_ptr<AbstractCardCommand>>(),
                                     false,
                                     ChannelControl::KEEP_OPEN);
                resetModificationsBufferCounter();

                /* We reopen a new session for the remaining commands to be sent */
                std::vector<std::shared_ptr<AbstractCardCommand>> dummy;
                processAtomicOpening(mCurrentWriteAccessLevel, dummy);

                /*
                * Clear the list and add the command that did not fit in the card modifications
                * buffer. We also update the usage counter without checking the result.
                */
                cardAtomicCommands.clear();
                cardAtomicCommands.push_back(command);

                /* Just update modifications buffer usage counter, ignore result (always false) */
                isSessionBufferOverflowed(neededSessionBufferSpace);
            } else {
                /* The command fits in the card modifications buffer, just add it to the list */
                cardAtomicCommands.push_back(command);
            }
        } else {
            /* This command does not affect the card modifications buffer */
            cardAtomicCommands.push_back(command);
        }
    }

    if (!cardAtomicCommands.empty()) {
        processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);
    }

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();
}

CardTransactionManager& CardTransactionManagerAdapter::processCardCommands()
{
    if (mSessionState == SessionState::SESSION_OPEN) {
        processCardCommandsInSession();
    } else {
        processCardCommandsOutOfSession(mChannelControl);
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processClosing()
{
    checkSessionOpen();

    bool atLeastOneReadCommand = false;
    bool sessionPreviouslyClosed = false;

    std::atomic<int> neededSessionBufferSpace;
    std::atomic<bool> overflow;

    std::vector<std::shared_ptr<AbstractCardCommand>> cardAtomicCommands;

    for (const auto& command : mCardCommandManager->getCardCommands()) {
        /*
         * Check if the command is a modifying one and get it status (overflow yes/no,
         * neededSessionBufferSpace). Iif the command overflows the session buffer in atomic
         * modification mode, an exception is raised.
         */
        if (checkModifyingCommand(command, overflow, neededSessionBufferSpace)) {
            if (overflow) {
                /*
                 * Reopen a session with the same access level if it was previously closed in
                 * this current processClosing
                 */
                if (sessionPreviouslyClosed) {

                std::vector<std::shared_ptr<AbstractCardCommand>> dummy;
                    processAtomicOpening(mCurrentWriteAccessLevel, dummy);
                }

                /*
                 * If at least one non-modifying was prepared, we use processAtomicCardCommands
                 * instead of processAtomicClosing to send the list
                 */
                if (atLeastOneReadCommand) {
                    processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);

                    /* Clear the list of commands sent */
                    cardAtomicCommands.clear();
                    processAtomicClosing(cardAtomicCommands, false, ChannelControl::KEEP_OPEN);
                    resetModificationsBufferCounter();
                    sessionPreviouslyClosed = true;
                    atLeastOneReadCommand = false;
                } else {
                    /* All commands in the list are 'modifying the card' */
                    processAtomicClosing(cardAtomicCommands, false, ChannelControl::KEEP_OPEN);

                    /* Clear the list of commands sent */
                    cardAtomicCommands.clear();
                    resetModificationsBufferCounter();
                    sessionPreviouslyClosed = true;
                }

                /*
                 * Add the command that did not fit in the card modifications
                 * buffer. We also update the usage counter without checking the result.
                 */
                cardAtomicCommands.push_back(command);

                /* Just update modifications buffer usage counter, ignore result (always false) */
                isSessionBufferOverflowed(neededSessionBufferSpace);
            } else {
                /* The command fits in the card modifications buffer, just add it to the list */
                cardAtomicCommands.push_back(command);
            }
        } else {
            /* This command does not affect the card modifications buffer */
            cardAtomicCommands.push_back(command);
            atLeastOneReadCommand = true;
        }
    }

    if (sessionPreviouslyClosed) {
        /* Reopen a session if necessary */
        std::vector<std::shared_ptr<AbstractCardCommand>> dummy;
        processAtomicOpening(mCurrentWriteAccessLevel, dummy);
    }

    if (atLeastOneReadCommand) {
        /* Execute the command */
        processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);
        cardAtomicCommands.clear();
    }

    /* Finally, close the session as requested */
    processAtomicClosing(cardAtomicCommands,
                         std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
                            ->isRatificationMechanismEnabled(),
                         mChannelControl);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processCancel()
{
    checkSessionOpen();

    /* Card ApduRequestAdapter List to hold Close Secure Session command */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    /* Build the card Close Session command (in "abort" mode since no signature is provided) */
    auto cmdCardCloseSession = std::make_shared<CmdCardCloseSession>(mCalypsoCard);

    apduRequests.push_back(cmdCardCloseSession->getApduRequest());

    /* Transfer card commands */
    std::shared_ptr<CardRequestSpi> cardRequest =
        std::make_shared<CardRequestAdapter>(apduRequests, false);

    const std::shared_ptr<CardResponseApi> cardResponse = safeTransmit(cardRequest,
                                                                       mChannelControl);

    try {
        cmdCardCloseSession->setApduResponse(cardResponse->getApduResponses()[0]).checkStatus();
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing the response to close session: " +
                                    e.getCommand().getName(),
                                    std::make_shared<CardCommandException>(e));
    }

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    /*
     * Session is now considered closed regardless the previous state or the result of the abort
     * session command sent to the card.
     */
    mSessionState = SessionState::SESSION_CLOSED;

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processVerifyPin(
    const std::vector<uint8_t>& pin)
{
    Assert::getInstance().isEqual(pin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

    if (!mCalypsoCard->isPinFeatureAvailable()) {
        throw UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
    }

    if (mCardCommandManager->hasCommands()) {
        throw IllegalStateException("No commands should have been prepared prior to a PIN " \
                                    "submission.");
    }

    /* CL-PIN-PENCRYPT.1 */
    if (mCardSecuritySettings != nullptr &&
       !std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
           ->isPinPlainTransmissionEnabled()) {

        /* CL-PIN-GETCHAL.1 */
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardGetChallenge>(mCalypsoCard->getCardClass()));

        /* Transmit and receive data with the card */
        processAtomicCardCommands(mCardCommandManager->getCardCommands(),
                                  ChannelControl::KEEP_OPEN);

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

        /* Get the encrypted PIN with the help of the SAM */
        std::vector<uint8_t> cipheredPin;
        try {
            cipheredPin = mSamCommandProcessor->getCipheredPinData(mCalypsoCard->getCardChallenge(),
                                                                   pin,
                                                                   std::vector<uint8_t>());
        } catch (const CalypsoSamCommandException& e) {
            throw SamAnomalyException(SAM_COMMAND_ERROR +
                                      "generating of the PIN ciphered data: " +
                                      e.getCommand().getName(),
                                      std::make_shared<CalypsoSamCommandException>(e));
        } catch (const ReaderBrokenCommunicationException& e) {
            throw SamIOException(SAM_READER_COMMUNICATION_ERROR +
                                 GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR,
                                 std::make_shared<ReaderBrokenCommunicationException>(e));
        } catch (const CardBrokenCommunicationException& e) {
            throw SamIOException(SAM_COMMUNICATION_ERROR +
                                 GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR,
                                 std::make_shared<CardBrokenCommunicationException>(e));
        }

        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardVerifyPin>(mCalypsoCard->getCardClass(), true, cipheredPin));
    } else {
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardVerifyPin>(mCalypsoCard->getCardClass(), false, pin));
    }

    /* Transmit and receive data with the card */
    processAtomicCardCommands(mCardCommandManager->getCardCommands(), mChannelControl);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processChangePin(
    const std::vector<uint8_t>& newPin)
{

    Assert::getInstance().isEqual(newPin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

    if (!mCalypsoCard->isPinFeatureAvailable()) {
        throw UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
    }

    if (mSessionState == SessionState::SESSION_OPEN) {
        throw IllegalStateException("'Change PIN' not allowed when a secure session is open.");
    }

    /* CL-PIN-MENCRYPT.1 */
    if (std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
            ->isPinPlainTransmissionEnabled()) {
        /* Transmission in plain mode */
        if (mCalypsoCard->getPinAttemptRemaining() >= 0) {
            mCardCommandManager->addRegularCommand(
                std::make_shared<CmdCardChangePin>(mCalypsoCard->getCardClass(), newPin));
        }
    } else {
        /* CL-PIN-GETCHAL.1 */
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardGetChallenge>(mCalypsoCard->getCardClass()));

        /* Transmit and receive data with the card */
        processAtomicCardCommands(mCardCommandManager->getCardCommands(),
                                  ChannelControl::KEEP_OPEN);

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

        /* Get the encrypted PIN with the help of the SAM */
        std::vector<uint8_t> newPinData;
        std::vector<uint8_t> currentPin(4); /* All zeros as required */
        try {
            newPinData =
                mSamCommandProcessor->getCipheredPinData(
                    mCalypsoCard->getCardChallenge(), currentPin, newPin);
        } catch (const CalypsoSamCommandException& e) {
            throw SamAnomalyException(SAM_COMMAND_ERROR +
                                      "generating of the PIN ciphered data: " +
                                      e.getCommand().getName(),
                                      std::make_shared<CalypsoSamCommandException>(e));
        } catch (const ReaderBrokenCommunicationException& e) {
            throw SamIOException(SAM_READER_COMMUNICATION_ERROR +
                                 GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR,
                                 std::make_shared<ReaderBrokenCommunicationException>(e));
        } catch (const CardBrokenCommunicationException& e) {
            throw SamIOException(SAM_COMMUNICATION_ERROR +
                                 GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR,
                                 std::make_shared<CardBrokenCommunicationException>(e));
        }

        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardChangePin>(mCalypsoCard->getCardClass(), newPinData));
    }

    /* Transmit and receive data with the card */
    processAtomicCardCommands(mCardCommandManager->getCardCommands(), mChannelControl);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::processChangeKey(const int keyIndex,
                                                                        const uint8_t newKif,
                                                                        const uint8_t newKvc,
                                                                        const uint8_t issuerKif,
                                                                        const uint8_t issuerKvc)
{
    if (mCalypsoCard->getProductType() == CalypsoCard::ProductType::BASIC) {
        throw UnsupportedOperationException("The 'Change Key' command is not available for this " \
                                            "card.");
    }

    if (mSessionState == SessionState::SESSION_OPEN) {
        throw IllegalStateException("'Change Key' not allowed when a secure session is open.");
    }

    Assert::getInstance().isInRange(keyIndex, 1, 3, "keyIndex");

    /* CL-KEY-CHANGE.1 */
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardGetChallenge>(mCalypsoCard->getCardClass()));

    /* Transmit and receive data with the card */
    processAtomicCardCommands(mCardCommandManager->getCardCommands(), ChannelControl::KEEP_OPEN);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    /* Get the encrypted key with the help of the SAM */
    try {
        const std::vector<uint8_t> encryptedKey =
            mSamCommandProcessor->getEncryptedKey(
                mCalypsoCard->getCardChallenge(), issuerKif, issuerKvc, newKif, newKvc);
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardChangeKey>(mCalypsoCard->getCardClass(),
                                               keyIndex,
                                               encryptedKey));
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "generating the encrypted key: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR +
                             GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR,
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR,
                             std::make_shared<CardBrokenCommunicationException>(e));
    }

    /* Transmit and receive data with the card */
    processAtomicCardCommands(mCardCommandManager->getCardCommands(), mChannelControl);

    /* Sets the flag indicating that the commands have been executed */
    mCardCommandManager->notifyCommandsProcessed();

    return *this;
}

const std::shared_ptr<CardResponseApi> CardTransactionManagerAdapter::safeTransmit(
    const std::shared_ptr<CardRequestSpi> cardRequest, const ChannelControl channelControl)
{
    try {
        return mCardReader->transmitCardRequest(cardRequest, channelControl);
    } catch (const ReaderBrokenCommunicationException& e) {
        throw CardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS,
                              std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw CardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS,
                              std::make_shared<CardBrokenCommunicationException>(e));
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::getSessionTerminalChallenge()
{
    std::vector<uint8_t> sessionTerminalChallenge;

    try {
        sessionTerminalChallenge = mSamCommandProcessor->getSessionTerminalChallenge();
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "getting the terminal challenge: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR + "getting the terminal challenge.",
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + "getting terminal challenge.",
                             std::make_shared<CardBrokenCommunicationException>(e));
    }

    return sessionTerminalChallenge;
}

const std::vector<uint8_t> CardTransactionManagerAdapter::getSessionTerminalSignature()
{
    std::vector<uint8_t> sessionTerminalSignature;

    try {
        sessionTerminalSignature = mSamCommandProcessor->getTerminalSignature();
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "getting the terminal signature: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + "getting the terminal signature.",
                             std::make_shared<CardBrokenCommunicationException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR + "getting the terminal signature.",
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    }

    return sessionTerminalSignature;
}

void CardTransactionManagerAdapter::checkCardSignature(const std::vector<uint8_t>& cardSignature)
{
    try {
        mSamCommandProcessor->authenticateCardSignature(cardSignature);
    } catch (const CalypsoSamSecurityDataException& e) {
        throw SessionAuthenticationException("The authentication of the card by the SAM has " \
                                             "failed.",
                                             std::make_shared<CalypsoSamSecurityDataException>(e));
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "authenticating the card signature: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR +
                             "authenticating the card signature.",
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + "authenticating the card signature.",
                             std::make_shared<CardBrokenCommunicationException>(e));
    }
}

void CardTransactionManagerAdapter::checkSvOperationStatus(
    const std::vector<uint8_t>& cardPostponedData)
{
    try {
        mSamCommandProcessor->checkSvStatus(cardPostponedData);
    } catch (const CalypsoSamSecurityDataException& e) {
        throw SvAuthenticationException("The checking of the SV operation by the SAM has failed.",
                                        std::make_shared<CalypsoSamSecurityDataException>(e));
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "checking the SV operation: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION,
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + CHECKING_THE_SV_OPERATION,
                             std::make_shared<CardBrokenCommunicationException>(e));
    }
}

void CardTransactionManagerAdapter::checkSessionOpen()
{
    if (mSessionState != SessionState::SESSION_OPEN) {
        std::stringstream ss;
        ss << "Bad session state. Current: " << mSessionState
           << ", expected: " << SessionState::SESSION_OPEN;
        throw  IllegalStateException(ss.str());
    }
}

void CardTransactionManagerAdapter::checkSessionNotOpen()
{
    if (mSessionState == SessionState::SESSION_OPEN) {
        std::stringstream ss;
        ss << "Bad session state. Current: " << mSessionState << ", expected: not open";
        throw IllegalStateException(ss.str());
    }
}

void CardTransactionManagerAdapter::checkCommandsResponsesSynchronization(const int commandsNumber,
                                                                          const int responsesNumber)
{
    if (commandsNumber != responsesNumber) {
        throw DesynchronizedExchangesException("The number of commands/responses does not match: " \
                                               "cmd=" +
                                               std::to_string(commandsNumber) +
                                               ", resp=" +
                                               std::to_string(responsesNumber));
        }
}

bool CardTransactionManagerAdapter::checkModifyingCommand(
    const std::shared_ptr<AbstractCardCommand> command,
    std::atomic<bool>& overflow,
    std::atomic<int>& neededSessionBufferSpace)
{
    if (command->isSessionBufferUsed()) {
        /* This command affects the card modifications buffer */
        neededSessionBufferSpace = command->getApduRequest()->getApdu().size() +
                                   SESSION_BUFFER_CMD_ADDITIONAL_COST -
                                   APDU_HEADER_LENGTH;

        if (isSessionBufferOverflowed(neededSessionBufferSpace)) {
            /*
             * Raise an exception if in atomic mode
             * CL-CSS-REQUEST.1
             * CL-CSS-SMEXCEED.1
             * CL-CSS-INFOCSS.1
             */
            if (!std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
                     ->isMultipleSessionEnabled()) {
                throw AtomicTransactionException("ATOMIC mode error! This command would overflow " \
                                                 "the card modifications buffer: " +
                                                 command->getName());
            }
            overflow = true;
        } else {
            overflow = false;
        }

        return true;
    } else {
        return false;
    }
}

bool CardTransactionManagerAdapter::isSessionBufferOverflowed(const int sessionBufferSizeConsumed)
{
    bool isSessionBufferFull = false;

    if (mCalypsoCard->isModificationsCounterInBytes()) {
        if (mModificationsCounter - sessionBufferSizeConsumed >= 0) {
            mModificationsCounter -= sessionBufferSizeConsumed;
        } else {
            mLogger->debug("Modifications buffer overflow! BYTESMODE, CURRENTCOUNTER = %, " \
                           "REQUIREMENT = %\n",
                           mModificationsCounter,
                           sessionBufferSizeConsumed);

            isSessionBufferFull = true;
        }
    } else {
        if (mModificationsCounter > 0) {
            mModificationsCounter--;
        } else {
            mLogger->debug("Modifications buffer overflow! COMMANDSMODE, CURRENTCOUNTER = %, " \
                           "REQUIREMENT = %\n",
                           mModificationsCounter,
                           1);

            isSessionBufferFull = true;
        }
    }

    return isSessionBufferFull;
}


void CardTransactionManagerAdapter::resetModificationsBufferCounter()
{
    mLogger->trace("Modifications buffer counter reset: PREVIOUSVALUE = %, NEWVALUE = %\n",
                   mModificationsCounter,
                   mCalypsoCard->getModificationsCounter());

    mModificationsCounter = mCalypsoCard->getModificationsCounter();
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

    return prepareSelectFile(ByteArrayUtil::twoBytesToInt(lid, 0));
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSelectFile(const uint16_t lid)
{
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardSelectFile>(mCalypsoCard->getCardClass(),
                                            mCalypsoCard->getProductType(),
                                            lid));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSelectFile(
    const SelectFileControl selectFileControl)
{
    /* Create the command and add it to the list of commands */
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardSelectFile>(mCalypsoCard->getCardClass(), selectFileControl));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareGetData(const GetDataTag tag)
{
    /* Create the command and add it to the list of commands */
    switch (tag) {
    case GetDataTag::FCI_FOR_CURRENT_DF:
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardGetDataFci>(mCalypsoCard->getCardClass()));
        break;
    case GetDataTag::FCP_FOR_CURRENT_FILE:
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardGetDataFcp>(mCalypsoCard->getCardClass()));
        break;
    case GetDataTag::EF_LIST:
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardGetDataEfList>(mCalypsoCard->getCardClass()));
        break;
    case GetDataTag::TRACEABILITY_INFORMATION:
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardGetDataTraceabilityInformation>(mCalypsoCard->getCardClass()));
        break;
    default:
        std::stringstream ss;
        ss << tag;
        throw UnsupportedOperationException("Unsupported Get Data tag: " + ss.str());
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecordFile(const uint8_t sfi,
                                                                             const int recordNumber)
{
    return prepareReadRecord(sfi, recordNumber);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecordFile(
    const uint8_t sfi,
    const int firstRecordNumber,
    const int numberOfRecords,
    const int recordSize)
{
    return prepareReadRecords(sfi,
                              firstRecordNumber,
                              firstRecordNumber + numberOfRecords - 1,
                              recordSize);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadCounterFile(
    const uint8_t sfi, const int countersNumber)
{
    return prepareReadCounter(sfi, countersNumber);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecord(const uint8_t sfi,
                                                                         const int recordNumber)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(recordNumber,
                                    CalypsoCardConstant::NB_REC_MIN,
                                    CalypsoCardConstant::NB_REC_MAX,
                                    RECORD_NUMBER);

    if (mSessionState == SessionState::SESSION_OPEN &&
       !std::dynamic_pointer_cast<CardReader>(mCardReader)->isContactless()) {
        throw IllegalStateException("Explicit record size is expected inside a secure session in " \
                                    "contact mode.");
    }

    auto cmdCardReadRecords =
        std::make_shared<CmdCardReadRecords>(mCalypsoCard->getCardClass(),
                                             sfi,
                                             recordNumber,
                                             CmdCardReadRecords::ReadMode::ONE_RECORD,
                                             0);
    mCardCommandManager->addRegularCommand(cmdCardReadRecords);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadRecords(
    const uint8_t sfi,
    const int fromRecordNumber,
    const int toRecordNumber,
    const int recordSize)
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
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadRecords>(mCalypsoCard->getCardClass(),
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
        const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();
        const int nbBytesPerRecord = recordSize + 2;
        const int nbRecordsPerApdu = mCalypsoCard->getPayloadCapacity() / nbBytesPerRecord;
        const int dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

        int currentRecordNumber = fromRecordNumber;
        int nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
        int currentLength;

        while (currentRecordNumber < toRecordNumber) {
            currentLength = nbRecordsRemainingToRead <= nbRecordsPerApdu ?
                                nbRecordsRemainingToRead * nbBytesPerRecord :
                                dataSizeMaxPerApdu;

            mCardCommandManager->addRegularCommand(
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
            mCardCommandManager->addRegularCommand(
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
    const int fromRecordNumber,
    const int toRecordNumber,
    const int offset,
    const int nbBytesToRead)
{
    if (mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3 &&
        mCalypsoCard->getProductType() != CalypsoCard::ProductType::LIGHT) {
        throw UnsupportedOperationException("The 'Read Record Multiple' command is not available " \
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

    const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();
    const int nbRecordsPerApdu = mCalypsoCard->getPayloadCapacity() / nbBytesToRead;

    int currentRecordNumber = fromRecordNumber;

    while (currentRecordNumber <= toRecordNumber) {
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadRecordMultiple>(cardClass,
                                                        sfi,
                                                        currentRecordNumber,
                                                        offset,
                                                        nbBytesToRead));
        currentRecordNumber += nbRecordsPerApdu;
    }

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadBinary(const uint8_t sfi,
                                                                         const int offset,
                                                                         const int nbBytesToRead)
{
    if (mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3) {
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

    if (sfi > 0 && offset > 255) { /* FFh */
        /* Tips to select the file: add a "Read Binary" command (read one byte at offset 0). */
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadBinary>(mCalypsoCard->getCardClass(), sfi, 0, 1));
    }

    const int payloadCapacity = mCalypsoCard->getPayloadCapacity();
    const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();

    int currentLength;
    int currentOffset = offset;
    int nbBytesRemainingToRead = nbBytesToRead;

    do {
        currentLength = std::min(nbBytesRemainingToRead, payloadCapacity);
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadBinary>(cardClass, sfi, currentOffset, currentLength));

        currentOffset += currentLength;
        nbBytesRemainingToRead -= currentLength;
    } while (nbBytesRemainingToRead > 0);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareReadCounter(
    const uint8_t sfi, const int nbCountersToRead)
{
    return prepareReadRecords(sfi, 1, 1, nbCountersToRead * 3);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSearchRecords(
    const std::shared_ptr<SearchCommandData> data)
{
    if (mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3) {
        throw UnsupportedOperationException("The 'Search Record Multiple' command is not " \
                                            "available for this card.");
    }

    auto dataAdapter = std::dynamic_pointer_cast<SearchCommandDataAdapter>(data);
    if (!dataAdapter) {
        throw IllegalArgumentException("The provided data must be an instance of " \
                                       "'SearchCommandDataAdapter' class.");
    }

    Assert::getInstance().notNull(data, "data")
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

    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardSearchRecordMultiple>(mCalypsoCard->getCardClass(), dataAdapter));

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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardAppendRecord>(mCalypsoCard->getCardClass(), sfi, recordData));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareUpdateRecord(
    const uint8_t sfi,
    const int recordNumber,
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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardUpdateRecord>(mCalypsoCard->getCardClass(),
                                              sfi,
                                              recordNumber,
                                              recordData));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareWriteRecord(
    const uint8_t sfi,
    const int recordNumber,
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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardWriteRecord>(mCalypsoCard->getCardClass(),
                                             sfi,
                                             recordNumber,
                                             recordData));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareUpdateBinary(
    const uint8_t sfi,
    const int offset,
    const std::vector<uint8_t>& data)
{
    return prepareUpdateOrWriteBinary(true, sfi, offset, data);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareWriteBinary(
    const uint8_t sfi,
    const int offset,
    const std::vector<uint8_t>& data)
{
    return prepareUpdateOrWriteBinary(false, sfi, offset, data);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareUpdateOrWriteBinary(
    const bool isUpdateCommand,
    const uint8_t sfi,
    const int offset,
    const std::vector<uint8_t>& data)
{
    if (mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3) {
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

    if (sfi > 0 && offset > 255) { /* FFh */
        /* Tips to select the file: add a "Read Binary" command (read one byte at offset 0) */
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadBinary>(mCalypsoCard->getCardClass(), sfi, 0, 1));
    }

    const int dataLength = data.size();
    const int payloadCapacity = mCalypsoCard->getPayloadCapacity();
    const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();

    int currentLength;
    int currentOffset = offset;
    int currentIndex = 0;

    do {
        currentLength = std::min(dataLength - currentIndex, payloadCapacity);

        mCardCommandManager->addRegularCommand(
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
    const int counterNumber,
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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardIncreaseOrDecrease>(isDecreaseCommand,
                                                    mCalypsoCard->getCardClass(),
                                                    sfi,
                                                    counterNumber,
                                                    incDecValue));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareIncreaseCounter(
    const uint8_t sfi, const int counterNumber, const int incValue)
{
    return prepareIncreaseOrDecreaseCounter(false, sfi, counterNumber, incValue);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareDecreaseCounter(
    const uint8_t sfi, const int counterNumber, const int decValue)
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
    if (!mCalypsoCard->isPinFeatureAvailable()) {
        throw UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
    }

    /* Create the command and add it to the list of commands */
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardVerifyPin>(mCalypsoCard->getCardClass()));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvGet(const SvOperation svOperation,
                                                                    const SvAction svAction)
{
    if (!mCalypsoCard->isSvFeatureAvailable()) {
        throw UnsupportedOperationException("Stored Value is not available for this card.");
    }

    if (std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
            ->isSvLoadAndDebitLogEnabled() &&
        !mCalypsoCard->isExtendedModeSupported()) {
        /*
         * @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
         * for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
         * CL-SV-GETNUMBER.1
         */
        const SvOperation operation1 = SvOperation::RELOAD == svOperation ? SvOperation::DEBIT :
                                                                            SvOperation::RELOAD;
        mCardCommandManager->addStoredValueCommand(
            std::make_shared<CmdCardSvGet>(mCalypsoCard->getCardClass(), mCalypsoCard, operation1),
            operation1);
    }

    mCardCommandManager->addStoredValueCommand(
        std::make_shared<CmdCardSvGet>(mCalypsoCard->getCardClass(), mCalypsoCard, svOperation),
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
    /* Create the initial command with the application data */
    auto svReloadCmdBuild = std::make_shared<CmdCardSvReload>(mCalypsoCard,
                                                              amount,
                                                              mCalypsoCard->getSvKvc(),
                                                              date,
                                                              time,
                                                              free);

    /* Get the security data from the SAM */
    std::vector<uint8_t> svReloadComplementaryData;
    try {
        svReloadComplementaryData =
            mSamCommandProcessor->getSvReloadComplementaryData(svReloadCmdBuild,
                                                               mCalypsoCard->getSvGetHeader(),
                                                               mCalypsoCard->getSvGetData());
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "preparing the SV reload command: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR + "preparing the SV reload command.",
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + "preparing the SV reload command.",
                             std::make_shared<CardBrokenCommunicationException>(e));
    }

    /* Finalize the SvReload command with the data provided by the SAM */
    svReloadCmdBuild->finalizeCommand(svReloadComplementaryData);

    /* Create and keep the CalypsoCardCommand */
    mCardCommandManager->addStoredValueCommand(svReloadCmdBuild, SvOperation::RELOAD);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvReload(const int amount)
{
    const std::vector<uint8_t> zero = {0x00, 0x00};

    prepareSvReload(amount, zero, zero, zero);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvDebit(
    const int amount,
    const std::vector<uint8_t>& date,
    const std::vector<uint8_t>& time)
{
    try {
        if (SvAction::DO == mSvAction) {
            prepareInternalSvDebit(amount, date, time);
        } else {
            prepareInternalSvUndebit(amount, date, time);
        }
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "preparing the SV debit/undebit command: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR +
                             "preparing the SV debit/undebit command.",
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR +
                             "preparing the SV debit/undebit command.",
                             std::make_shared<CardBrokenCommunicationException>(e));
    }

    return *this;
}

void CardTransactionManagerAdapter::prepareInternalSvDebit(const int amount,
                                                           const std::vector<uint8_t>& date,
                                                           const std::vector<uint8_t>& time)
{
    if (!std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
            ->isSvNegativeBalanceAuthorized() &&
        (mCalypsoCard->getSvBalance() - amount) < 0) {
        throw IllegalStateException("Negative balances not allowed.");
    }

    /* Create the initial command with the application data */
    auto svDebitCmdBuild = std::make_shared<CmdCardSvDebit>(mCalypsoCard,
                                                            amount,
                                                            mCalypsoCard->getSvKvc(),
                                                            date,
                                                            time);

    /* Get the security data from the SAM */
    const std::vector<uint8_t> svDebitComplementaryData =
        mSamCommandProcessor->getSvDebitComplementaryData(svDebitCmdBuild,
                                                          mCalypsoCard->getSvGetHeader(),
                                                          mCalypsoCard->getSvGetData());

    /* Finalize the SvDebit command with the data provided by the SAM */
    svDebitCmdBuild->finalizeCommand(svDebitComplementaryData);

    /* Create and keep the CalypsoCardCommand */
    mCardCommandManager->addStoredValueCommand(svDebitCmdBuild, SvOperation::DEBIT);
}

void CardTransactionManagerAdapter::prepareInternalSvUndebit(const int amount,
                                                             const std::vector<uint8_t>& date,
                                                             const std::vector<uint8_t>& time)
{
    /* Create the initial command with the application data */
    auto svUndebitCmdBuild = std::make_shared<CmdCardSvUndebit>(mCalypsoCard,
                                                                amount,
                                                                mCalypsoCard->getSvKvc(),
                                                                date,
                                                                time);

    /* Get the security data from the SAM */
    std::vector<uint8_t> svDebitComplementaryData;
    svDebitComplementaryData =
        mSamCommandProcessor->getSvUndebitComplementaryData(svUndebitCmdBuild,
                                                            mCalypsoCard->getSvGetHeader(),
                                                            mCalypsoCard->getSvGetData());

    /* Finalize the SvUndebit command with the data provided by the SAM */
    svUndebitCmdBuild->finalizeCommand(svDebitComplementaryData);

    /* Create and keep the CalypsoCardCommand */
    mCardCommandManager->addStoredValueCommand(svUndebitCmdBuild, SvOperation::DEBIT);
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvDebit(const int amount)
{
    const std::vector<uint8_t> zero = {0x00, 0x00};

    prepareSvDebit(amount, zero, zero);

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvReadAllLogs()
{
    if (!mCalypsoCard->isSvFeatureAvailable()) {
        throw UnsupportedOperationException("Stored Value is not available for this card.");
    }

    if (mCalypsoCard->getApplicationSubtype() !=
        CalypsoCardConstant::STORED_VALUE_FILE_STRUCTURE_ID) {
        throw UnsupportedOperationException("The currently selected application is not an SV " \
                                            "application.");
    }

    /* Reset SV data in CalypsoCard if any */
    const std::vector<uint8_t> dummy;
    mCalypsoCard->setSvData(0, dummy, dummy, 0, 0, nullptr, nullptr);
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
    if (mCalypsoCard->isDfInvalidated()) {
        throw IllegalStateException("This card is already invalidated.");
    }

    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardInvalidate>(mCalypsoCard->getCardClass()));

    return *this;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareRehabilitate()
{
    if (!mCalypsoCard->isDfInvalidated()) {
        throw IllegalStateException("This card is not invalidated.");
    }

    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardRehabilitate>(mCalypsoCard->getCardClass()));

    return *this;
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

/* SESSION STATE -------------------------------------------------------------------------------- */

std::ostream& operator<<(std::ostream& os, const CardTransactionManagerAdapter::SessionState ss)
{
    switch (ss) {
    case CardTransactionManagerAdapter::SessionState::SESSION_UNINITIALIZED:
        os << "SESSION_UNINITIALIZED";
        break;
    case CardTransactionManagerAdapter::SessionState::SESSION_OPEN:
        os << "SESSION_OPEN";
        break;
    case CardTransactionManagerAdapter::SessionState::SESSION_CLOSED:
        os << "SESSION_CLOSED";
        break;
    default:
        os << "UNKONWN";
        break;
    }

    return os;
}

}
}
}
