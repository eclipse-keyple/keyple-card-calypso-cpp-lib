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
#include "ApduRequestSpi.h"
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
using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

/* CARD TRANSACTION MANAGER ADAPTER ------------------------------------------------------------- */
const std::string CardTransactionManagerAdapter::PATTERN_1_BYTE_HEX = "%020Xh";

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
  const std::shared_ptr<CardSecuritySettingAdapter> cardSecuritySetting)
: mCardReader(std::dynamic_pointer_cast<ProxyReaderApi>(cardReader)),
  mCardSecuritySetting(cardSecuritySetting),
  mSamCommandProcessor(cardSecuritySetting ?
                       std::make_shared<SamCommandProcessor>(calypsoCard, cardSecuritySetting) :
                       nullptr),
  mCalypsoCard(std::dynamic_pointer_cast<CalypsoCardAdapter>(calypsoCard)),
  mSessionState(SessionState::SESSION_UNINITIALIZED),
  mCurrentWriteAccessLevel(WriteAccessLevel::DEBIT), /* had to set a default value to please MSVC */
  mModificationsCounter(mCalypsoCard->getModificationsCounter()),
  mCardCommandManager(std::make_shared<CardCommandManager>()),
  mSvAction(SvAction::DO), /* had to set a default value to please MSVC */
  mIsSvOperationInsideSession(false), /* CL-SV-1PCSS.1 */
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
    return mCardSecuritySetting;
}

const std::string CardTransactionManagerAdapter::getTransactionAuditData() const
{
    return "";
}

void CardTransactionManagerAdapter::processAtomicOpening(
    const WriteAccessLevel writeAccessLevel,
    std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands)
{
    if (mCardSecuritySetting == nullptr) {
        throw IllegalStateException("No security settings are available.");
    }

    mCalypsoCard->backupFiles();

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

    /* Compute the SAM challenge */
    const std::vector<uint8_t> samChallenge = getSamChallenge();

    /* Build the card Open Secure Session command */
    auto cmdCardOpenSession =
        std::make_shared<CmdCardOpenSession>(
            mCalypsoCard->getProductType(),
            static_cast<uint8_t>(static_cast<int>(writeAccessLevel) + 1),
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

    mSessionState = SessionState::SESSION_OPEN;

    /* Open a secure session, transmit the commands to the card and keep channel open */
    const std::shared_ptr<CardResponseApi> cardResponse =
        transmitCardRequest(cardRequest, ChannelControl::KEEP_OPEN);

    /* Retrieve the list of R-APDUs */
    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponses =
        cardResponse->getApduResponses();

    /* Parse all the responses and fill the CalypsoCard object with the command data */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cardCommands,
                                                  apduResponses,
                                                  true);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(std::string(CARD_COMMAND_ERROR) +
                                   "processing the response to open session: " +
                                    e.getCommand().getName(),
                                    std::make_shared<CardCommandException>(e));
    }

    /* Build the "Digest Init" SAM command from card Open Session */

    /* The card KIF/KVC (KVC may be null for card Rev 1.0) */
    const std::shared_ptr<uint8_t> cardKif = cmdCardOpenSession->getSelectedKif();
    const std::shared_ptr<uint8_t> cardKvc = cmdCardOpenSession->getSelectedKvc();

    const std::string logCardKif = cardKif != nullptr ? std::to_string(*cardKif) : "null";
    const std::string logCardKvc = cardKvc != nullptr ? std::to_string(*cardKvc) : "null";
    mLogger->debug("processAtomicOpening => opening: CARDCHALLENGE=%, CARDKIF=%, CARDKVC=%\n",
                   ByteArrayUtil::toHex(cmdCardOpenSession->getCardChallenge()),
                   logCardKif,
                   logCardKvc);

    const std::shared_ptr<uint8_t> kvc =
        mSamCommandProcessor->computeKvc(writeAccessLevel, cardKvc);
    const std::shared_ptr<uint8_t> kif =
        mSamCommandProcessor->computeKif(writeAccessLevel, cardKif, kvc);

    if (!mCardSecuritySetting->isSessionKeyAuthorized(kif, kvc)) {
        const std::string logKif = kif != nullptr ? std::to_string(*kif) : "null";
        const std::string logKvc = kvc != nullptr ? std::to_string(*kvc) : "null";
        throw UnauthorizedKeyException("Unauthorized key error: KIF=" + logKif + ", KVC=" + logKvc);
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
                                             apduResponses[0]->getDataOut());

    /*
     * Add all commands data to the digest computation. The first command in the list is the
     * open secure session command. This command is not included in the digest computation, so
     * we skip it and start the loop at index 1.
     * Add requests and responses to the digest processor
     */
    mSamCommandProcessor->pushCardExchangedData(apduRequests, apduResponses, 1);
}

void CardTransactionManagerAdapter::abortSecureSessionSilently()
{
    if (mSessionState == SessionState::SESSION_OPEN) {

        try {
            processCancel();
        } catch (const RuntimeException& e) {
            mLogger->error("An error occurred while aborting the current secure session.", e);
        }

        mSessionState = SessionState::SESSION_CLOSED;
    }
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSetCounter(
    const uint8_t sfi, const uint8_t counterNumber, const int newValue)
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
    if (mSessionState == SessionState::SESSION_OPEN) {
        mSamCommandProcessor->pushCardExchangedData(apduRequests, apduResponses, 0);
    }

    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cardCommands,
                                                  apduResponses,
                                                  mSessionState == SessionState::SESSION_OPEN);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing responses to card commands: " +
                                   e.getCommand().getName(),
                                   std::make_shared<CardCommandException>(e));
    }
}

void CardTransactionManagerAdapter::processAtomicClosing(
    const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands,
    const bool isRatificationMechanismEnabled,
    const ChannelControl channelControl)
{
    /* Get the list of C-APDU to transmit */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests = getApduRequests(cardCommands);

    /* Build the expected APDU respones of the card commands */
    const std::vector<std::shared_ptr<ApduResponseApi>> expectedApduResponses =
        buildAnticipatedResponses(cardCommands);

    /* Add all commands data to the digest computation: commands and expected responses */
    mSamCommandProcessor->pushCardExchangedData(apduRequests, expectedApduResponses, 0);

    /*
     * All SAM digest operations will now run at once.
     * Get Terminal Signature from the latest response.
     */
    const std::vector<uint8_t> sessionTerminalSignature = getSessionTerminalSignature();

    /* Build the last "Close Secure Session" card command */
    auto cmdCardCloseSession =
        std::make_shared<CmdCardCloseSession>(mCalypsoCard,
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
            CmdCardRatificationBuilder::getApduRequest(mCalypsoCard->getCardClass()));
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
        const std::shared_ptr<AbstractApduException> cause =
            std::dynamic_pointer_cast<AbstractApduException>(e.getCause());
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
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cardCommands,
                                                  apduResponses,
                                                  true);
    } catch (const CardCommandException& e) {
        throw CardAnomalyException(CARD_COMMAND_ERROR +
                                   "processing of responses preceding the close of the session: " +
                                   e.getCommand().getName(),
                                   std::make_shared<CardCommandException>(e));
    }

    mSessionState = SessionState::SESSION_CLOSED;

    /* Check the card's response to Close Secure Session */
    try {
        CalypsoCardUtilAdapter::updateCalypsoCard(mCalypsoCard,
                                                  cmdCardCloseSession,
                                                  closeSecureSessionApduResponse,
                                                  false);
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
}

int CardTransactionManagerAdapter::getCounterValue(const uint8_t sfi, const int counter)
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
    const uint8_t sfi, const std::vector<int>& counters)
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
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;

    if (!cardCommands.empty()) {
        for (const auto& command : cardCommands) {
            if (command->getCommandRef() == CalypsoCardCommand::INCREASE ||
                command->getCommandRef() == CalypsoCardCommand::DECREASE) {

                auto cmdA = std::dynamic_pointer_cast<CmdCardIncreaseOrDecrease>(command);
                apduResponses.push_back(
                    buildAnticipatedIncreaseDecreaseResponse(
                        cmdA->getCommandRef() == CalypsoCardCommand::DECREASE,
                        getCounterValue(cmdA->getSfi(), cmdA->getCounterNumber()),
                        cmdA->getIncDecValue()));

            } else if (command->getCommandRef() == CalypsoCardCommand::INCREASE_MULTIPLE ||
                       command->getCommandRef() == CalypsoCardCommand::DECREASE_MULTIPLE) {

                auto cmdB = std::dynamic_pointer_cast<CmdCardIncreaseOrDecreaseMultiple>(command);
                const std::map<const int, const int>& counterNumberToIncDecValueMap =
                    cmdB->getCounterNumberToIncDecValueMap();
                apduResponses.push_back(
                    buildAnticipatedIncreaseDecreaseMultipleResponse(
                        cmdB->getCommandRef() == CalypsoCardCommand::DECREASE_MULTIPLE,
                        getCounterValues(cmdB->getSfi(),
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
    try {
        checkSessionNotOpen();

        /* CL-KEY-INDEXPO.1 */
        mCurrentWriteAccessLevel = writeAccessLevel;

        /* Create a sublist of AbstractCardCommand to be sent atomically */
        std::vector<std::shared_ptr<AbstractCardCommand>> cardAtomicCommands;

        for (const auto& command : mCardCommandManager->getCardCommands()) {

            /* Check if the command is a modifying command */
            if (command->isSessionBufferUsed()) {
                mModificationsCounter -= computeCommandSessionBufferSize(command);
                if (mModificationsCounter < 0) {
                    checkMultipleSessionEnabled(command);

                    /* Process and intermedisate secure session with the current commands */
                    processAtomicOpening(mCurrentWriteAccessLevel, cardAtomicCommands);
                    std::vector<std::shared_ptr<AbstractCardCommand>> empty;
                    processAtomicClosing(empty, false, ChannelControl::KEEP_OPEN);

                    /* Reset and update the buffer counter */
                    mModificationsCounter = mCalypsoCard->getModificationsCounter();
                    mModificationsCounter -= computeCommandSessionBufferSize(command);

                    /* Clear the list */
                    cardAtomicCommands.clear();
                }
            }

            cardAtomicCommands.push_back(command);
        }

        processAtomicOpening(mCurrentWriteAccessLevel, cardAtomicCommands);

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

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
    if (!mCardSecuritySetting->isMultipleSessionEnabled()) {
        throw AtomicTransactionException("ATOMIC mode error! This command would overflow the " \
                                         "card modifications buffer: " +
                                         command->getName());
    }
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
    try {
        /* A session is open, we have to care about the card modifications buffer */
        std::vector<std::shared_ptr<AbstractCardCommand>> cardAtomicCommands;
        bool isAtLeastOneReadCommand = false;

        for (const auto& command : mCardCommandManager->getCardCommands()) {

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
                    std::vector<std::shared_ptr<AbstractCardCommand>> empty;
                    processAtomicOpening(mCurrentWriteAccessLevel, empty);

                    /* Reset and update the buffer counter */
                    mModificationsCounter = mCalypsoCard->getModificationsCounter();
                    mModificationsCounter -= computeCommandSessionBufferSize(command);
                    isAtLeastOneReadCommand = false;

                    /* Clear the list */
                    cardAtomicCommands.clear();
                }
            } else {
                isAtLeastOneReadCommand = true;
            }
        }

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
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
    try {
        checkSessionOpen();

        std::vector<std::shared_ptr<AbstractCardCommand>> cardAtomicCommands;
        bool isAtLeastOneReadCommand = false;

        for (const auto& command : mCardCommandManager->getCardCommands()) {

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
                    std::vector<std::shared_ptr<AbstractCardCommand>> empty;
                    processAtomicOpening(mCurrentWriteAccessLevel, empty);

                   /* Reset and update the buffer counter */
                   mModificationsCounter = mCalypsoCard->getModificationsCounter();
                   mModificationsCounter -= computeCommandSessionBufferSize(command);
                   isAtLeastOneReadCommand = false;

                   /* Clear the list */
                   cardAtomicCommands.clear();
                }

            } else {
                isAtLeastOneReadCommand = true;
            }
        }

        if (isAtLeastOneReadCommand) {
            processAtomicCardCommands(cardAtomicCommands, ChannelControl::KEEP_OPEN);
            cardAtomicCommands.clear();
        }

        processAtomicClosing(cardAtomicCommands,
                             mCardSecuritySetting->isRatificationMechanismEnabled(),
                             mChannelControl);

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

        return *this;

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

CardTransactionManager& CardTransactionManagerAdapter::processCancel()
{
    checkSessionOpen();

    mCalypsoCard->restoreFiles();

    /* Build the card Close Session command (in "abort" mode since no signature is provided) */
    auto cmdCardCloseSession = std::make_shared<CmdCardCloseSession>(mCalypsoCard);

    /* Card ApduRequestAdapter List to hold close SecureSession command */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;
    apduRequests.push_back(cmdCardCloseSession->getApduRequest());

    /* Transfer card commands */
    const std::shared_ptr<CardRequestSpi> cardRequest =
        std::make_shared<CardRequestAdapter>(apduRequests, false);
    const std::shared_ptr<CardResponseApi> cardResponse =
        transmitCardRequest(cardRequest, mChannelControl);

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
    try {
        Assert::getInstance().isEqual(pin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!mCalypsoCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
        }

        if (mCardCommandManager->hasCommands()) {
            throw IllegalStateException("No commands should have been prepared prior to a PIN " \
                                        "submission.");
        }

        /* CL-PIN-PENCRYPT.1 */
        if (mCardSecuritySetting != nullptr &&
            !mCardSecuritySetting->isPinPlainTransmissionEnabled()) {

            /* CL-PIN-GETCHAL.1 */
            mCardCommandManager->addRegularCommand(
                std::make_shared<CmdCardGetChallenge>(mCalypsoCard->getCardClass()));

            /* Transmit and receive data with the card */
            processAtomicCardCommands(mCardCommandManager->getCardCommands(),
                                    ChannelControl::KEEP_OPEN);

            /* Sets the flag indicating that the commands have been executed */
            mCardCommandManager->notifyCommandsProcessed();

            /* Get the encrypted PIN with the help of the SAM */
            std::vector<uint8_t> cipheredPin = getSamCipherPinData(pin, std::vector<uint8_t>());

            mCardCommandManager->addRegularCommand(
                std::make_shared<CmdCardVerifyPin>(mCalypsoCard->getCardClass(),
                                                   true,
                                                   cipheredPin));
        } else {
            mCardCommandManager->addRegularCommand(
                std::make_shared<CmdCardVerifyPin>(mCalypsoCard->getCardClass(), false, pin));
        }

        /* Transmit and receive data with the card */
        processAtomicCardCommands(mCardCommandManager->getCardCommands(), mChannelControl);

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

        return *this;

    } catch (const RuntimeException& e) {
        abortSecureSessionSilently();
        throw e;
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::getSamCipherPinData(
    const std::vector<uint8_t>& currentPin, const std::vector<uint8_t>& newPin)
{
    try {
        return mSamCommandProcessor->getCipheredPinData(mCalypsoCard->getCardChallenge(),
                                                        currentPin,
                                                        newPin);
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  " generating of the PIN ciphered data: " +
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
}

CardTransactionManager& CardTransactionManagerAdapter::processChangePin(
    const std::vector<uint8_t>& newPin)
{
    try {
        Assert::getInstance().isEqual(newPin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!mCalypsoCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(PIN_NOT_AVAILABLE_ERROR);
        }

        if (mSessionState == SessionState::SESSION_OPEN) {
            throw IllegalStateException("'Change PIN' not allowed when a secure session is open.");
        }

        /* CL-PIN-MENCRYPT.1 */
        if (mCardSecuritySetting->isPinPlainTransmissionEnabled()) {

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
            std::vector<uint8_t> currentPin(4); /* All zeros as required */
            std::vector<uint8_t> newPinData = getSamCipherPinData(currentPin, newPin);

            mCardCommandManager->addRegularCommand(
                std::make_shared<CmdCardChangePin>(mCalypsoCard->getCardClass(), newPinData));
        }

        /* Transmit and receive data with the card */
        processAtomicCardCommands(mCardCommandManager->getCardCommands(), mChannelControl);

        /* Sets the flag indicating that the commands have been executed */
        mCardCommandManager->notifyCommandsProcessed();

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

const std::shared_ptr<CardResponseApi> CardTransactionManagerAdapter::transmitCardRequest(
    const std::shared_ptr<CardRequestSpi> cardRequest, const ChannelControl channelControl)
{
    /* Process SAM operations first for SV if needed */
    if (mCardCommandManager->getSvLastModifyingCommand() != nullptr) {
        finalizeSvCommand();
    }

    /* Process card request */
    std::shared_ptr<CardResponseApi> cardResponse = nullptr;

    try {
        cardResponse = mCardReader->transmitCardRequest(cardRequest, channelControl);
    } catch (const ReaderBrokenCommunicationException& e) {
        throw CardIOException(CARD_READER_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS,
                              std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw CardIOException(CARD_COMMUNICATION_ERROR + TRANSMITTING_COMMANDS,
                              std::make_shared<CardBrokenCommunicationException>(e));
    } catch (const UnexpectedStatusWordException& e) {
        mLogger->debug("A card command has failed: %\n", e.getMessage());
        cardResponse = e.getCardResponse();
    }

    return cardResponse;
}

void CardTransactionManagerAdapter::finalizeSvCommand()
{
    try {
        std::vector<uint8_t> svComplementaryData;

        if (mCardCommandManager->getSvLastModifyingCommand()->getCommandRef() ==
            CalypsoCardCommand::SV_RELOAD) {

            /* SV RELOAD: get the security data from the SAM */
            auto svCommand = std::dynamic_pointer_cast<CmdCardSvReload>(
                                 mCardCommandManager->getSvLastModifyingCommand());

            svComplementaryData =
                mSamCommandProcessor->getSvReloadComplementaryData(svCommand,
                                                                   mCalypsoCard->getSvGetHeader(),
                                                                   mCalypsoCard->getSvGetData());

            /* Finalize the SV command with the data provided by the SAM */
            svCommand->finalizeCommand(svComplementaryData);

        } else {

            /* SV DEBIT/UNDEBIT: get the security data from the SAM */
            auto svCommand = std::dynamic_pointer_cast<CmdCardSvDebitOrUndebit>(
                                 mCardCommandManager->getSvLastModifyingCommand());

            svComplementaryData =
                mSamCommandProcessor->getSvDebitOrUndebitComplementaryData(
                    svCommand->getCommandRef() == CalypsoCardCommand::SV_DEBIT,
                    svCommand,
                    mCalypsoCard->getSvGetHeader(),
                    mCalypsoCard->getSvGetData());

            /* Finalize the SV command with the data provided by the SAM */
            svCommand->finalizeCommand(svComplementaryData);
        }
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                  "preparing the SV command: " +
                                  e.getCommand().getName(),
                                  std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR +
                             "preparing the SV command.",
                             std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + "preparing the SV command.",
                             std::make_shared<CardBrokenCommunicationException>(e));
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::getSamChallenge()
{
    try {
        return mSamCommandProcessor->getChallenge();
    } catch (const CalypsoSamCommandException& e) {
        throw SamAnomalyException(SAM_COMMAND_ERROR +
                                "getting the SAM challenge: " +
                                e.getCommand().getName(),
                                std::make_shared<CalypsoSamCommandException>(e));
    } catch (const ReaderBrokenCommunicationException& e) {
        throw SamIOException(SAM_READER_COMMUNICATION_ERROR + "getting the SAM challenge.",
                            std::make_shared<ReaderBrokenCommunicationException>(e));
    } catch (const CardBrokenCommunicationException& e) {
        throw SamIOException(SAM_COMMUNICATION_ERROR + "getting SAM challenge.",
                            std::make_shared<CardBrokenCommunicationException>(e));
    }
}

const std::vector<uint8_t> CardTransactionManagerAdapter::getSessionTerminalSignature()
{
    try {
        return mSamCommandProcessor->getTerminalSignature();
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


int CardTransactionManagerAdapter::computeCommandSessionBufferSize(
    std::shared_ptr<AbstractCardCommand> command)
{
    return mCalypsoCard->isModificationsCounterInBytes() ? 
               command->getApduRequest()->getApdu().size() + 
                   SESSION_BUFFER_CMD_ADDITIONAL_COST - 
                   APDU_HEADER_LENGTH : 
               1;
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

    return prepareSelectFile(static_cast<uint16_t>(ByteArrayUtil::twoBytesToInt(lid, 0)));
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
                                             static_cast<uint8_t>(0));
    mCardCommandManager->addRegularCommand(cmdCardReadRecords);

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
        const uint8_t nbBytesPerRecord = recordSize + 2;
        const uint8_t nbRecordsPerApdu =
            static_cast<uint8_t>(mCalypsoCard->getPayloadCapacity() / nbBytesPerRecord);
        const uint8_t dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

        uint8_t currentRecordNumber = fromRecordNumber;
        uint8_t nbRecordsRemainingToRead = toRecordNumber - fromRecordNumber + 1;
        uint8_t currentLength;

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
    const uint8_t fromRecordNumber,
    const uint8_t toRecordNumber,
    const uint8_t offset,
    const uint8_t nbBytesToRead)
{
    if (mCalypsoCard->getProductType() != CalypsoCard::ProductType::PRIME_REVISION_3 &&
        mCalypsoCard->getProductType() != CalypsoCard::ProductType::LIGHT) {
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

    const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();
    const uint8_t nbRecordsPerApdu =
        static_cast<uint8_t>(mCalypsoCard->getPayloadCapacity() / nbBytesToRead);

    uint8_t currentRecordNumber = fromRecordNumber;

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

CardTransactionManager& CardTransactionManagerAdapter::prepareReadBinary(
    const uint8_t sfi, const uint8_t offset, const uint8_t nbBytesToRead)
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

    /* C++: no need to check offset > 255, forced by value type */
    if (sfi > 0) {
        /* Tips to select the file: add a "Read Binary" command (read one byte at offset 0). */
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadBinary>(mCalypsoCard->getCardClass(),
                                                sfi,
                                                static_cast<uint8_t>(0),
                                                static_cast<uint8_t>(1)));
    }

    const uint8_t payloadCapacity = mCalypsoCard->getPayloadCapacity();
    const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();

    uint8_t currentLength;
    uint8_t currentOffset = offset;
    uint8_t nbBytesRemainingToRead = nbBytesToRead;

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
    const uint8_t sfi, const uint8_t nbCountersToRead)
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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardUpdateRecord>(mCalypsoCard->getCardClass(),
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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardWriteRecord>(mCalypsoCard->getCardClass(),
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

    /* C++: no need to check offset > 255, forced by value type */
    if (sfi > 0) {
        /* Tips to select the file: add a "Read Binary" command (read one byte at offset 0) */
        mCardCommandManager->addRegularCommand(
            std::make_shared<CmdCardReadBinary>(mCalypsoCard->getCardClass(),
                                                sfi,
                                                static_cast<uint8_t>(0),
                                                static_cast<uint8_t>(1)));
    }

    const uint8_t dataLength = static_cast<uint8_t>(data.size());
    const uint8_t payloadCapacity = mCalypsoCard->getPayloadCapacity();
    const CalypsoCardClass cardClass = mCalypsoCard->getCardClass();

    uint8_t currentLength;
    uint8_t currentOffset = offset;
    uint8_t currentIndex = 0;

    do {
        currentLength = static_cast<uint8_t>(
                            std::min(static_cast<int>(dataLength - currentIndex),
                                     static_cast<int>(payloadCapacity)));

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
    mCardCommandManager->addRegularCommand(
        std::make_shared<CmdCardIncreaseOrDecrease>(isDecreaseCommand,
                                                    mCalypsoCard->getCardClass(),
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

    /* CL-SV-CMDMODE.1 */
    std::shared_ptr<CalypsoSam> calypsoSam = mCardSecuritySetting->getCalypsoSam();
    const bool useExtendedMode = mCalypsoCard->isExtendedModeSupported() &&
                                 (calypsoSam == nullptr || 
                                  calypsoSam->getProductType() == CalypsoSam::ProductType::SAM_C1);

    if (mCardSecuritySetting->isSvLoadAndDebitLogEnabled() && !useExtendedMode) {

        /*
         * @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit logs are requested
         * for a non rev3.2 card add two SvGet commands (for RELOAD then for DEBIT).
         * CL-SV-GETNUMBER.1
         */
        const SvOperation operation1 = SvOperation::RELOAD == svOperation ? SvOperation::DEBIT :
                                                                            SvOperation::RELOAD;
        mCardCommandManager->addStoredValueCommand(
            std::make_shared<CmdCardSvGet>(mCalypsoCard->getCardClass(), operation1, false),
            operation1);
    }

    mCardCommandManager->addStoredValueCommand(
        std::make_shared<CmdCardSvGet>(mCalypsoCard->getCardClass(), svOperation, useExtendedMode),
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
    auto svReloadCmdBuild = std::make_shared<CmdCardSvReload>(mCalypsoCard->getCardClass(),
                                                              amount,
                                                              mCalypsoCard->getSvKvc(),
                                                              date,
                                                              time,
                                                              free,
                                                              isExtendedModeAllowed());

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

void CardTransactionManagerAdapter::checkSvInsideSession()
{
    /* CL-SV-1PCSS.1 */
    if (mSessionState == SessionState::SESSION_OPEN) {
       
        if (!mIsSvOperationInsideSession) {
            mIsSvOperationInsideSession = true;
        } else {
            throw IllegalStateException("Only one SV operation is allowed per Secure Session.");
        }
    }
}

bool CardTransactionManagerAdapter::isExtendedModeAllowed() const
{
    std::shared_ptr<CalypsoSam> calypsoSam = mCardSecuritySetting->getCalypsoSam();
    
    return mCalypsoCard->isExtendedModeSupported() && 
           calypsoSam->getProductType() == CalypsoSam::ProductType::SAM_C1;
}

CardTransactionManager& CardTransactionManagerAdapter::prepareSvDebit(
    const int amount,
    const std::vector<uint8_t>& date,
    const std::vector<uint8_t>& time)
{
    checkSvInsideSession();

    if (mSvAction == SvAction::DO &&
        !mCardSecuritySetting->isSvNegativeBalanceAuthorized() &&
        (mCalypsoCard->getSvBalance() - amount) < 0) {
        throw IllegalStateException("Negative balances not allowed.");
    }

    /* Create the initial command with the application data */
    auto command = std::make_shared<CmdCardSvDebitOrUndebit>(mSvAction == SvAction::DO,
                                                             mCalypsoCard->getCardClass(),
                                                             amount,
                                                             mCalypsoCard->getSvKvc(),
                                                             date,
                                                             time,
                                                             isExtendedModeAllowed());

    /* Create and keep the CalypsoCardCommand */
    mCardCommandManager->addStoredValueCommand(command, SvOperation::DEBIT);

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
