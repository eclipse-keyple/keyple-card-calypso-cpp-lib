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
#include "CardSecuritySettingAdapter.h"
#include "SamCommandProcessor.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
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
 *   <li>CL-SW-CHECK.1
 *   <li>CL-CSS-SMEXCEED.1
 *   <li>CL-CSS-6D006E00.1
 *   <li>CL-CSS-UNEXPERR.1
 *   <li>CL-CSS-INFOCSS.1
 * </ul>
 *
 * @since 2.0.0
 */
class CardTransactionManagerAdapter final : public CardTransactionManager {
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
     * (package-private)<br>
     * Creates an instance of CardTransactionManager for secure operations.
     *
     * <p>Secure operations are enabled by the presence of CardSecuritySetting.
     *
     * @param cardReader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @param cardSecuritySetting The security settings.
     * @since 2.0.0
     */
    CardTransactionManagerAdapter(
        const std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySettingAdapter> cardSecuritySetting);

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
    CardTransactionManager& processChangeKey(const uint8_t keyIndex,
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
    CardTransactionManager& prepareReadRecordFile(const uint8_t sfi, const uint8_t recordNumber)
        final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadRecordFile(const uint8_t sfi,
                                                  const uint8_t firstRecordNumber,
                                                  const uint8_t numberOfRecords,
                                                  const uint8_t recordSize) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadCounterFile(const uint8_t sfi, const uint8_t countersNumber)
        final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadRecord(const uint8_t sfi, const uint8_t recordNumber)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadRecords(const uint8_t sfi,
                                               const uint8_t fromRecordNumber,
                                               const uint8_t toRecordNumber,
                                               const uint8_t recordSize) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadRecordsPartially(const uint8_t sfi,
                                                        const uint8_t fromRecordNumber,
                                                        const uint8_t toRecordNumber,
                                                        const uint8_t offset,
                                                        const uint8_t nbBytesToRead) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadBinary(const uint8_t sfi,
                                              const uint8_t offset,
                                              const uint8_t nbBytesToRead) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareReadCounter(const uint8_t sfi, const uint8_t nbCountersToRead)
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
                                                const uint8_t recordNumber,
                                                const std::vector<uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareWriteRecord(const uint8_t sfi,
                                               const uint8_t recordNumber,
                                               const std::vector<uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareUpdateBinary(const uint8_t sfi,
                                                const uint8_t offset,
                                                const std::vector<uint8_t>& data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareWriteBinary(const uint8_t sfi,
                                               const uint8_t offset,
                                               const std::vector<uint8_t>& data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareIncreaseCounter(const uint8_t sfi,
                                                   const uint8_t counterNumber,
                                                   const int incValue) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareDecreaseCounter(const uint8_t sfi,
                                                   const uint8_t counterNumber,
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
                                              const uint8_t counterNumber,
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
    class ApduResponseAdapter final : public ApduResponseApi {
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
     *
     */
    static const std::string PATTERN_1_BYTE_HEX;

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
     *
     */
    static const std::shared_ptr<ApduResponseApi> RESPONSE_OK;
    static const std::shared_ptr<ApduResponseApi> RESPONSE_OK_POSTPONED;

    /**
     * The reader for the card
     */
    const std::shared_ptr<ProxyReaderApi> mCardReader;

    /**
     * The card security settings used to manage the secure session
     */
    const std::shared_ptr<CardSecuritySettingAdapter> mCardSecuritySetting;

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
     * Flag indicating if an SV operation has been performed during the current secure session.
     */
    bool mIsSvOperationInsideSession;


    /**
     * The ChannelControl action
     */
    ChannelControl mChannelControl;

    /**
     * Create an ApduRequestAdapter List from a AbstractCardCommand List.
     *
     * @param cardCommands a list of card commands.
     * @return An empty list if there is no command.
     */
    const std::vector<std::shared_ptr<ApduRequestSpi>> getApduRequests(
        const std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands);

    /**
     * (private)<br>
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
     * (private)<br>
     * Throws an exception if the multiple session is not enabled.
     *
     * @param command The command.
     * @throw AtomicTransactionException If the multiple session is not allowed.
     */
    void checkMultipleSessionEnabled(std::shared_ptr<AbstractCardCommand> command) const;

    /**
     * (private)<br>
     * Returns the cipher PIN data from the SAM (ciphered PIN transmission or PIN change).
     *
     * @param currentPin The current PIN.
     * @param newPin The new PIN, or null in case of a PIN presentation.
     * @return A not null array.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed (only for SV
     *        operations).
     * @throw SamAnomalyException If a SAM error occurs (only for SV operations).
     */
    const std::vector<uint8_t> getSamCipherPinData(const std::vector<uint8_t>& currentPin,
                                                   const std::vector<uint8_t>& newPin);

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
     * @param cardCommands The list of last card commands to transmit inside the secure session.
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
    int getCounterValue(const uint8_t sfi, const int counter);

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
    const std::map<const int, const int> getCounterValues(const uint8_t sfi,
                                                          const std::vector<int>& counters);

    /**
     * Builds an anticipated response to an Increase/Decrease command
     *
     * @param isDecreaseCommand True if it is a "Decrease" command, false if it is an * "Increase"
     *        command.
     * @param currentCounterValue The current counter value.
     * @param incDecValue The increment/decrement value.
     * @return An ApduResponseApi containing the expected bytes
     */
    const std::shared_ptr<ApduResponseApi> buildAnticipatedIncreaseDecreaseResponse(
        const bool isDecreaseCommand, const int currentCounterValue, const int incDecValue);

    /**
     * Builds an anticipated response to an Increase/Decrease Multiple command
     *
     * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
     *        "Increase Multiple" command.
     * @param counterNumberToCurrentValueMap The values of the counters currently known in the file.
     * @param counterNumberToIncDecValueMap The values to be decremented/incremented.
     * @return An ApduResponseApi containing the expected bytes.
     */
    const std::shared_ptr<ApduResponseApi> buildAnticipatedIncreaseDecreaseMultipleResponse(
        const bool isDecreaseCommand,
        const std::map<const int, const int>& counterNumberToCurrentValueMap,
        const std::map<const int, const int>& counterNumberToIncDecValueMap);

    /**
     * (private)<br>
     * Builds the anticipated expected responses to the commands sent in processClosing.<br>
     * These commands are supposed to be "modifying commands" only.
     *
     * @param cardCommands the list of card commands sent.
     * @return An empty list if there is no command.
     * @throw IllegalStateException if the anticipation process failed
     */
    const std::vector<std::shared_ptr<ApduResponseApi>> buildAnticipatedResponses(
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
     * @throw SamIOException If the communication with the SAM or the SAM reader failed (only for SV
     *        operations).
     * @throw SamAnomalyException If a SAM error occurs (only for SV operations).
     */
    const std::shared_ptr<CardResponseApi> transmitCardRequest(
        const std::shared_ptr<CardRequestSpi> cardRequest, const ChannelControl channelControl);

    /**
     * Gets the terminal challenge from the SAM, and raises exceptions if necessary.
     * (private)<br>
     * Finalizes the last SV modifying command.
     *
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     * @throw SamAnomalyException If a SAM error occurs.
     */
    void finalizeSvCommand();

    /**
     * Gets the SAM challenge from the SAM, and raises exceptions if necessary.
     *
     * @return A not null reference.
     * @throw SamAnomalyException If SAM returned an unexpected response.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     */
    const std::vector<uint8_t> getSamChallenge();

    /**
     * Gets the terminal signature from the SAM, and raises exceptions if necessary.
     *
     * @return A not null reference.
     * @throw SamAnomalyException If SAM returned an unexpected response.
     * @throw SamIOException If the communication with the SAM or the SAM reader failed.
     * @throw DesynchronizedExchangesException if the APDU SAM exchanges are out of sync.
     */
    const std::vector<uint8_t> getSessionTerminalSignature();

    /**
     * (private)<br>
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
     * (private)<br>
     * Checks if a Secure Session is not open, raises an exception if not
     *
     * @throw IllegalStateException if a session is open
     */
    void checkSessionNotOpen();

    /** (private)<br>
     * Computes the session buffer size of the provided command.<br>
     * The size may be a number of bytes or 1 depending on the card specificities.
     *
     * @param command The command.
     * @return A positive value.
     */
    int computeCommandSessionBufferSize(std::shared_ptr<AbstractCardCommand> command);

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
                                                       const uint8_t offset,
                                                       const std::vector<uint8_t>& data);

     /**
     * (private)
     *
     * <p>Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
     */
    CardTransactionManager& prepareIncreaseOrDecreaseCounter(const bool isDecreaseCommand,
                                                             const uint8_t sfi,
                                                             const uint8_t counterNumber,
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
     * (private)<br>
     * Open a single Secure Session.
     *
     * @param writeAccessLevel access level of the session (personalization, load or debit).
     * @param cardCommands the card commands inside session.
     * @throw IllegalStateException if no CardSecuritySetting is available.
     * @throw CardTransactionException if a functional error occurs (including card and SAM IO
     *        errors).
     */
    void processAtomicOpening(
        const WriteAccessLevel writeAccessLevel,
        std::vector<std::shared_ptr<AbstractCardCommand>>& cardCommands);

    /**
     * (private)<br>
     * Aborts the secure session without raising any exception.
     */
    void abortSecureSessionSilently();

    /**
     * Prepares an SV Undebit (partially or totally cancels the last SV debit command).
     *
     * <p>It consists in canceling a previous debit. <br>
     * Note: the key used is the debit key
     *
     * @param amount the amount to be subtracted, positive integer in the range 0..32767
     * @param date 2-byte free value.
     * @param time 2-byte free value.
     * @param useExtendedMode True if the extended mode must be used.
     */
    void prepareInternalSvUndebit(const int amount,
                                  const std::vector<uint8_t>& date,
                                  const std::vector<uint8_t>& time,
                                  const bool useExtendedMode);

    /**
     * (private)<br>
     * Checks if only one modifying SV command is prepared inside the current secure session.
     *
     * @throw IllegalStateException If more than SV command is prepared.
     */
    void checkSvInsideSession();

    /**
     * (private)<br>
     *
     * @return True if the extended mode of the SV command is allowed.
     */
    bool isSvExtendedModeAllowed();

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
