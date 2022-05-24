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

#pragma once

#include <atomic>
#include <memory>
#include <ostream>

/* Calypsonet Terminal Calypso */
#include "CardSecuritySetting.h"
#include "CardTransactionManager.h"
#include "SearchCommandData.h"
#include "SvAction.h"
#include "WriteAccessLevel.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"
#include "ChannelControl.h"
#include "ProxyReaderApi.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CardCommandManager.h"
#include "SamCommandProcessor.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace keyple::card::calypso;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Implementation of CardTransactionManager.
 *
 * <ul>
 *   <li>CL-APP-ISOL.1
 *   <li>CL-CMD-SEND.1
 *   <li>CL-CMD-RECV.1
 *   <li>CL-CMD-CASE.1CardTransactionManager
 *   <li>CL-CMD-LCLE.1
 *   <li>CL-CMD-DATAIN.1
 *   <li>CL-C1-5BYTE.1
 *   <li>CL-C1-MAC.1
 *   <li>CL-C4-LE.1
 *   <li>CL-CLA-CMD.1
 *   <li>CL-RFU-FIELDCMD.1
 *   <li>CL-RFU-VALUECMD.1
 *   <li>CL-RFU-FIELDRSP.1
 *   <li>CL-SW-ANALYSIS.1
 *   <li>CL-SW-SUCCESS.1
 *   <li>CL-SF-SFI.1
 *   <li>CL-PERF-HFLOW.1
 *   <li>CL-CSS-INFOEND.1
 * </ul>
 *
 * @since 2.0.0
 */
class CardTransactionManagerAdapter : public CardTransactionManager {
public:
    /**
     *
     */
    enum class SessionState {
        /**
         * Initial state of a card transaction. The card must have been previously selected
         */
        SESSION_UNINITIALIZED,

        /**
         * The secure session is active
         */
        SESSION_OPEN,

        /**
         * The secure session is closed
         */
        SESSION_CLOSED
    };

    /**
     * Creates an instance of CardTransactionManager for secure operations.
     *
     * <p>Secure operations are enabled by the presence of CardSecuritySetting.
     *
     * @param cardReader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @param cardSecuritySetting The security settings.
     * @since 2.0.0
     */
    CardTransactionManagerAdapter(const std::shared_ptr<CardReader> cardReader,
                                  const std::shared_ptr<CalypsoCard> calypsoCard,
                                  const std::shared_ptr<CardSecuritySetting> cardSecuritySetting);

    /**
     * Creates an instance of CardTransactionManager for non-secure operations.
     *
     * @param cardReader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @since 2.0.0
     */
    CardTransactionManagerAdapter(const std::shared_ptr<CardReader> cardReader,
                                  const std::shared_ptr<CalypsoCard> calypsoCard);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<CardReader> getCardReader() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<CalypsoCard> getCalypsoCard() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<CardSecuritySetting> getCardSecuritySetting() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string getTransactionAuditData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processOpening(const WriteAccessLevel writeAccessLevel) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processCardCommands() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processClosing() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processCancel() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processVerifyPin(const std::vector<uint8_t>& pin) final;
    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processChangePin(const std::vector<uint8_t>& newPin) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& processChangeKey(const int keyIndex,
                                             const uint8_t newKif,
                                             const uint8_t newKvc,
                                             const uint8_t issuerKif,
                                             const uint8_t issuerKvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareReleaseCardChannel() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareSelectFile(const std::vector<uint8_t>& lid) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareSelectFile(const uint16_t lid) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSelectFile(const SelectFileControl selectFileControl) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareGetData(const GetDataTag tag) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadRecordFile(const uint8_t sfi, const int recordNumber) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadRecordFile(const uint8_t sfi,
                                                  const int firstRecordNumber,
                                                  const int numberOfRecords,
                                                  const int recordSize) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadCounterFile(const uint8_t sfi, const int countersNumber)
        final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadRecord(const uint8_t sfi, const int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadRecords(const uint8_t sfi,
                                               const int fromRecordNumber,
                                               const int toRecordNumber,
                                               const int recordSize) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadRecordsPartially(const uint8_t sfi,
                                                        const int fromRecordNumber,
                                                        const int toRecordNumber,
                                                        const int offset,
                                                        const int nbBytesToRead) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadBinary(const uint8_t sfi,
                                              const int offset,
                                              const int nbBytesToRead) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadCounter(const uint8_t sfi, const int nbCountersToRead)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareSearchRecords(const std::shared_ptr<SearchCommandData> data)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareAppendRecord(const uint8_t sfi,
                                                const std::vector<uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareUpdateRecord(const uint8_t sfi,
                                                const int recordNumber,
                                                const std::vector<uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareWriteRecord(const uint8_t sfi,
                                               const int recordNumber,
                                               const std::vector<uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareUpdateBinary(const uint8_t sfi,
                                                const int offset,
                                                const std::vector<uint8_t>& data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareWriteBinary(const uint8_t sfi,
                                               const int offset,
                                               const std::vector<uint8_t>& data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareIncreaseCounter(const uint8_t sfi,
                                                   const int counterNumber,
                                                   const int incValue) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareDecreaseCounter(const uint8_t sfi,
                                                   const int counterNumber,
                                                   const int decValue) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareDecreaseCounters(
        const uint8_t sfi,
        const std::map<const int, const int>& counterNumberToDecValueMap) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareIncreaseCounters(
        const uint8_t sfi,
        const std::map<const int, const int>& counterNumberToIncValueMap) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSetCounter(const uint8_t sfi,
                                              const int counterNumber,
                                              const int newValue) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareCheckPinStatus() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.
     */
    CardTransactionManager& prepareSvGet(const SvOperation svOperation, const SvAction svAction)
        final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvReload(const int amount,
                                            const std::vector<uint8_t>& date,
                                            const std::vector<uint8_t>& time,
                                            const std::vector<uint8_t>& free) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvReload(const int amount) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvDebit(const int amount,
                                           const std::vector<uint8_t>& date,
                                           const std::vector<uint8_t>& time) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvDebit(const int amount) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvReadAllLogs() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareInvalidate() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareRehabilitate() final;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const SessionState ss);


private:
    /**
     * (private)<br>
     * Adapter of ApduResponseApi used to create anticipated card responses.
     */
    class ApduResponseAdapter : public ApduResponseApi {
    public:
        /**
         *
         */
        friend class CardTransactionManagerAdapter;

        /**
         * Constructor
         */
        ApduResponseAdapter(const std::vector<uint8_t>& apdu);

        /**
         * {@inheritDoc}
         */
        const std::vector<uint8_t>& getApdu() const override;

        /**
         * {@inheritDoc}
         */
        const std::vector<uint8_t> getDataOut() const override;

        /**
         * {@inheritDoc}
         */
        int getStatusWord() const override;

    private:
        /**
         *
         */
        const std::vector<uint8_t> mApdu;

        /**
         *
         */
        const int mStatusWord;
    };

    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CardTransactionManagerAdapter));

    /**
     * Prefix/suffix used to compose exception messages
     */
    static const std::string CARD_READER_COMMUNICATION_ERROR;
    static const std::string CARD_COMMUNICATION_ERROR;
    static const std::string CARD_COMMAND_ERROR;
    static const std::string SAM_READER_COMMUNICATION_ERROR ;
    static const std::string SAM_COMMUNICATION_ERROR;
    static const std::string SAM_COMMAND_ERROR;
    static const std::string PIN_NOT_AVAILABLE_ERROR;
    static const std::string GENERATING_OF_THE_PIN_CIPHERED_DATA_ERROR;
    static const std::string GENERATING_OF_THE_KEY_CIPHERED_DATA_ERROR;
    static const std::string TRANSMITTING_COMMANDS;
    static const std::string CHECKING_THE_SV_OPERATION;
    static const std::string UNEXPECTED_EXCEPTION;
    static const std::string RECORD_NUMBER;

    /**
     * Commands that modify the content of the card in session have a cost on the session buffer
     * equal to the length of the outgoing data plus 6 bytes
     */
    static const int SESSION_BUFFER_CMD_ADDITIONAL_COST;
    static const int APDU_HEADER_LENGTH;

    /**
     *
     */
    static const std::string OFFSET;

    /**
     * The reader for the card
     */
    const std::shared_ptr<ProxyReaderApi> mCardReader;

    /**
     * The card security settings used to manage the secure session
     */
    const std::shared_ptr<CardSecuritySetting> mCardSecuritySettings;

    /**
     * The SAM commands processor
     */
    std::shared_ptr<SamCommandProcessor> mSamCommandProcessor;

    /**
     * The current CalypsoCard
     */
    const std::shared_ptr<CalypsoCardAdapter> mCalypsoCard;

    /**
     * The type of the notified event
     */
    SessionState mSessionState;

    /**
     * The current secure session access level: PERSO, RELOAD, DEBIT
     */
    WriteAccessLevel mCurrentWriteAccessLevel;

    /**
     * Modifications counter management
     */
    int mModificationsCounter;

    /**
     * The object for managing card commands
     */
    std::shared_ptr<CardCommandManager> mCardCommandManager;

    /**
     * The current Store Value action
     */
    SvAction mSvAction;

    /**
     * The ChannelControl action
     */
    ChannelControl mChannelControl;

    /**
     *
     */
    static const std::shared_ptr<ApduResponseApi> RESPONSE_OK;
    static const std::shared_ptr<ApduResponseApi> RESPONSE_OK_POSTPONED;

    /**
     * Create an ApduRequestAdapter List from a AbstractCardCommand List.
     *
     * @param cardCommands a list of card commands.
     * @return The ApduRequestAdapter list
     */
    const std::vector<std::shared_ptr<ApduRequestSpi>> getApduRequests(
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands);

    /**
     * Process card commands in a Secure Session.
     *
     * <ul>
     *   <li>On the card reader, generates a CardRequest with channelControl set to KEEP_OPEN, and
     *       ApduRequests with the card commands.
     *   <li>In case the secure session is active, the "cache" of SAM commands is completed with the
     *       corresponding Digest Update commands.
     *   <li>If a session is open and channelControl is set to CLOSE_AFTER, the current card session
     *       is aborted
     *   <li>Returns the corresponding card CardResponse.
     * </ul>
     *
     * @param cardCommands the card commands inside session.
     * @param channelControl indicated if the card channel of the card reader must be closed after
     *        the last command.
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors)
     */
    void processAtomicCardCommands(
        const std::vector<std::shared_ptr<AbstractCardCommand>> cardCommands,
        const ChannelControl channelControl);

    /**
     * Close the Secure Session.
     *
     * <ul>
     *   <li>The SAM cache is completed with the Digest Update commands related to the new card
     *       commands to be sent and their anticipated responses. A Digest Close command is also
     *       added to the SAM command cache.
     *   <li>On the SAM session reader side, a CardRequest is transmitted with SAM commands from the
     *       command cache. The SAM command cache is emptied.
     *   <li>The SAM certificate is retrieved from the Digest Close response. The terminal signature
     *       is identified.
     *   <li>Then, on the card reader, a CardRequest is transmitted with a ChannelControl set
     *       to CLOSE_AFTER or KEEP_OPEN depending on whether or not prepareReleaseCardChannel was
     *       invoked, and apduRequests including the new card commands to send in the session, a
     *       Close Session command (defined with the SAM certificate), and optionally a
     *       ratificationCommand.
     *       <ul>
     *         <li>The management of ratification is conditioned by the mode of communication.
     *             <ul>
     *               <li>If the communication mode is CONTACTLESS, a specific ratification command
     *                   is sent after the Close Session command. No ratification is requested in
     *                   the Close Session command.
     *               <li>If the communication mode is CONTACTS, no ratification command is sent
     *                   after the Close Session command. Ratification is requested in the Close
     *                   Session command.
     *             </ul>
     *         <li>Otherwise, the card Close Secure Session command is defined to directly set the
     *             card as ratified.
     *       </ul>
     *   <li>The card responses of the cardModificationCommands are compared with the
     *       cardAnticipatedResponses. The card signature is identified from the card Close Session
     *       response.
     *   <li>The card certificate is recovered from the Close Session response. The card signature
     *       is identified.
     *   <li>Finally, on the SAM session reader, a Digest Authenticate is automatically operated in
     *       order to verify the card signature.
     *   <li>Returns the corresponding card CardResponse.
     * </ul>
     *
     * The method is marked as deprecated because the advanced variant defined below must be used at
     * the application level.
     *
     * @param cardModificationCommands a list of commands that can modify the card memory content.
     * @param cardAnticipatedResponses a list of anticipated card responses to the modification
     *        commands.
     * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
     *        ratification command must be sent.
     * @param channelControl indicates if the card channel of the card reader must be closed after
     *        the last command.
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors)
     */
    void processAtomicClosing(
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardModificationCommands,
        const std::vector<std::shared_ptr<ApduResponseApi>>& cardAnticipatedResponses,
        const bool isRatificationMechanismEnabled,
        const ChannelControl channelControl);

    /**
     * Advanced variant of processAtomicClosing in which the list of expected responses is
     * determined from previous reading operations.
     *
     * @param cardCommands a list of commands that can modify the card memory content.
     * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
     *        ratification command must be sent.
     * @param channelControl indicates if the card channel of the card reader must be closed after
     *        the last command.
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors)
     */
    void processAtomicClosing(
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands,
        const bool isRatificationMechanismEnabled,
        const ChannelControl channelControl);

    /**
     * (private)
     *
     * <p>Gets the value of the designated counter
     *
     * @param sfi the SFI of the EF containing the counter.
     * @param counter the number of the counter.
     * @return The value of the counter
     * @throw IllegalStateException If the counter is not found.
     */
    int getCounterValue(const int sfi, const int counter);

    /**
     * (private)
     *
     * <p>Gets the value of the all counters of the designated file
     *
     * @param sfi The SFI of the EF containing the counter.
     * @param counters The list of expected counters.
     * @return A map containing the counters.
     * @throw IllegalStateException If one of the expected counter was found.
     */
    const std::map<const int, const int> getCounterValues(const int sfi,
                                                          const std::vector<int>& counters);

    /**
     * Create an anticipated response to an Increase/Decrease command
     *
     * @param isDecreaseCommand True if it is a "Decrease" command, false if it is an * "Increase"
     *        command.
     * @param currentCounterValue The current counter value.
     * @param incDecValue The increment/decrement value.
     * @return An ApduResponseApi containing the expected bytes
     */
    const std::shared_ptr<ApduResponseApi> createIncreaseDecreaseResponse(
        const bool isDecreaseCommand, const int currentCounterValue, const int incDecValue);

    /**
     * Create an anticipated response to an Increase/Decrease Multiple command
     *
     * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
     *        "Increase Multiple" command.
     * @param counterNumberToCurrentValueMap The values of the counters currently known in the file.
     * @param counterNumberToIncDecValueMap The values to be decremented/incremented.
     * @return An ApduResponseApi containing the expected bytes.
     */
    const std::shared_ptr<ApduResponseApi> createIncreaseDecreaseMultipleResponse(
        const bool isDecreaseCommand,
        const std::map<const int, const int>& counterNumberToCurrentValueMap,
        const std::map<const int, const int>& counterNumberToIncDecValueMap);

    /**
     * Get the anticipated response to the command sent in processClosing.<br>
     * These commands are supposed to be "modifying commands" i.e.
     * Increase/Decrease/UpdateRecord/WriteRecord ou AppendRecord.
     *
     * @param cardCommands the list of card commands sent.
     * @return The list of the anticipated responses.
     * @throw IllegalStateException if the anticipation process failed
     */
    const std::vector<std::shared_ptr<ApduResponseApi>> getAnticipatedResponses(
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands);

    /**
     * Process all prepared card commands (outside a Secure Session).
     *
     * <p>Note: commands prepared prior to the invocation of this method shall not require the use
     * of a SAM.
     *
     * @param channelControl indicates if the card channel of the card reader must be closed after
     *        the last command.
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors)
     */
    void processCardCommandsOutOfSession(const ChannelControl channelControl);

    /**
     * Process all prepared card commands in a Secure Session.
     *
     * <p>The multiple session mode is handled according to the session settings.
     *
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors)
     */
    void processCardCommandsInSession();

    /**
     * (private)<br>
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @param channelControl The channel control.
     * @return The card response.
     * @throw CardIOException If the communication with the card or the card reader failed.
     * @throw IllegalStateException If the card returned an unexpected response.
     */
    const std::shared_ptr<CardResponseApi> safeTransmit(
        const std::shared_ptr<CardRequestSpi> cardRequest, const ChannelControl channelControl);

    /**
     * Gets the terminal challenge from the SAM, and raises exceptions if necessary.
     *
     * @return A not null reference.
     * @throw SamAnomalyException If SAM returned an unexpected response.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     */
    const std::vector<uint8_t> getSessionTerminalChallenge();

    /**
     * Gets the terminal signature from the SAM, and raises exceptions if necessary.
     *
     * @return A not null reference.
     * @throw SamAnomalyException If SAM returned an unexpected response.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     */
    const std::vector<uint8_t> getSessionTerminalSignature();

    /**
     * Ask the SAM to verify the signature of the card, and raises exceptions if necessary.
     *
     * @param cardSignature The card signature.
     * @throw SessionAuthenticationException If the card authentication failed.
     * @throw SamAnomalyException If SAM returned an unexpected response.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     */
    void checkCardSignature(const std::vector<uint8_t>& cardSignature);

    /**
     * Ask the SAM to verify the SV operation status from the card postponed data, raises exceptions
     * if needed.
     *
     * @param cardPostponedData The postponed data from the card.
     * @throw SvAuthenticationException If the SV verification failed.
     * @throw SamAnomalyException If SAM returned an unexpected response.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     */
    void checkSvOperationStatus(const std::vector<uint8_t>& cardPostponedData);

    /**
     * Checks if a Secure Session is open, raises an exception if not
     *
     * @throw IllegalStateException if no session is open
     */
    void checkSessionOpen();

    /**
     * Checks if a Secure Session is not open, raises an exception if not
     *
     * @throw IllegalStateException if a session is open
     */
    void checkSessionNotOpen();

    /**
     * Checks if the number of responses matches the number of commands.<br>
     * Throw a {@link DesynchronizedExchangesException} if not.
     *
     * @param commandsNumber the number of commands.
     * @param responsesNumber the number of responses.
     * @throw DesynchronizedExchangesException if the test failed
     */
    void checkCommandsResponsesSynchronization(const int commandsNumber, const int responsesNumber);

     /**
     * Checks the provided command from the session buffer overflow management perspective<br>
     * A exception is raised if the session buffer is overflowed in ATOMIC modification mode.<br>
     * Returns false if the command does not affect the session buffer.<br>
     * Sets the overflow flag and the neededSessionBufferSpace value according to the characteristics
     * of the command in other cases.
     *
     * @param command the command.
     * @param overflow flag set to true if the command overflowed the buffer.
     * @param neededSessionBufferSpace updated with the size of the buffer consumed by the command.
     * @return True if the command modifies the content of the card, false if not
     * @throw AtomicTransactionException if the command overflows the buffer in ATOMIC modification
     *        mode
     */
    bool checkModifyingCommand(const std::shared_ptr<AbstractCardCommand> command,
                               std::atomic<bool>& overflow,
                               std::atomic<int>& neededSessionBufferSpace);

    /**
     * Checks whether the requirement for the modifications buffer of the command provided in argument
     * is compatible with the current usage level of the buffer.
     *
     * <p>If it is compatible, the requirement is subtracted from the current level and the method
     * returns false. If this is not the case, the method returns true and the current level is left
     * unchanged.
     *
     * @param sessionBufferSizeConsumed session buffer requirement.
     * @return True or false
     */
    bool isSessionBufferOverflowed(const int sessionBufferSizeConsumed);

    /**
     * Initialized the modifications buffer counter to its maximum value for the current card
     */
    void resetModificationsBufferCounter();

    /**
     * (private)<br>
     * Prepare an "Update/Write Binary" command.
     *
     * @param isUpdateCommand True if it is an "Update Binary" command, false if it is a "Write
     *        Binary" command.
     * @param sfi The SFI.
     * @param offset The offset.
     * @param data The data to update/write.
     * @return The current instance.
     */
    CardTransactionManager& prepareUpdateOrWriteBinary(const bool isUpdateCommand,
                                                       const uint8_t sfi,
                                                       const int offset,
                                                       const std::vector<uint8_t>& data);

     /**
     * (private)
     *
     * <p>Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
     */
    CardTransactionManager& prepareIncreaseOrDecreaseCounter(const bool isDecreaseCommand,
                                                             const uint8_t sfi,
                                                             const int counterNumber,
                                                             const int incDecValue);

    /**
     * (private)
     *
     * <p>Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters.
     */
    CardTransactionManager& prepareIncreaseOrDecreaseCounters(
        const bool isDecreaseCommand,
        const uint8_t sfi,
        const std::map<const int, const int>& counterNumberToIncDecValueMap);

    /**
     * Open a single Secure Session.
     *
     * @param writeAccessLevel access level of the session (personalization, load or debit).
     * @param cardCommands the card commands inside session.
     * @throw IllegalStateException if no CardTransactionManager is available
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors)
     */
    void processAtomicOpening(
        const WriteAccessLevel writeAccessLevel,
        std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands);

    /**
     * Prepares an SV Undebit (partially or totally cancels the last SV debit command).
     *
     * <p>It consists in canceling a previous debit. <br>
     * Note: the key used is the debit key
     *
     * @param amount the amount to be subtracted, positive integer in the range 0..32767
     * @param date 2-byte free value.
     * @param time 2-byte free value.
     */
    void prepareInternalSvUndebit(const int amount,
                                  const std::vector<uint8_t>& date,
                                  const std::vector<uint8_t>& time);

    /**
     * Schedules the execution of a <b>SV Debit</b> command to decrease the current SV balance.
     *
     * <p>It consists in decreasing the current balance of the SV by a certain amount.
     *
     * <p>Note: the key used is the debit key
     *
     * @param amount the amount to be subtracted, positive integer in the range 0..32767
     * @param date 2-byte free value.
     * @param time 2-byte free value.
     */
    void prepareInternalSvDebit(const int amount,
                                const std::vector<uint8_t>& date,
                                const std::vector<uint8_t>& time);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const ApduResponseAdapter& ara);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<ApduResponseAdapter> ara);
};

}
}
}
