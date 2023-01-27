/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
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
#include "CommonSignatureComputationData.h"
#include "CommonSignatureVerificationData.h"
#include "SearchCommandData.h"
#include "SvAction.h"
#include "WriteAccessLevel.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"
#include "CardRequestSpi.h"
#include "CardResponseApi.h"
#include "ChannelControl.h"
#include "ProxyReaderApi.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CardSecuritySettingAdapter.h"
#include "CardControlSamTransactionManagerAdapter.h"

/* Keyple Core Util */
#include "Any.h"
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::card::spi;
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
class CardTransactionManagerAdapter final
: public CommonTransactionManagerAdapter<CardTransactionManager,
                                         CardSecuritySetting,
                                         CardSecuritySettingAdapter>,
  public CardTransactionManager {
public:
    /**
     * (package-private)<br>
     * Creates an instance of CardTransactionManager.
     *
     * <p>Secure operations are enabled by the presence of {@link CardSecuritySetting}.
     *
     * @param cardReader The reader through which the card communicates.
     * @param card The initial card data provided by the selection process.
     * @param securitySetting The security settings.
     * @since 2.0.0
     */
    CardTransactionManagerAdapter(const std::shared_ptr<ProxyReaderApi> cardReader,
                                  const std::shared_ptr<CalypsoCardAdapter> card,
                                  const std::shared_ptr<CardSecuritySettingAdapter> securitySetting);

    /**
     * C++: Ugly hack to avoid ambiguous method lookup. This function should be final in
     * CommonTransactionManagerAdapter
     *
     * @since 2.2.0
     */
    const std::vector<std::vector<uint8_t>>& getTransactionAuditData() const final
    {
        return CommonTransactionManagerAdapter::getTransactionAuditData();
    }

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
     * @deprecated Use getSecuritySetting() instead.
     */
    const std::shared_ptr<CardSecuritySetting> getCardSecuritySetting() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processOpening(const WriteAccessLevel writeAccessLevel) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<CardSecuritySetting> getSecuritySetting() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    CardTransactionManager& prepareComputeSignature(const any data) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    CardTransactionManager& prepareVerifySignature(const any data) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    CardTransactionManager& processCommands() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated Use processCommands() instead.
     */
    CardTransactionManager& processCardCommands() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processClosing() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processCancel() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& processVerifyPin(const std::vector<uint8_t>& pin) override;
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
    CardTransactionManager& prepareReleaseCardChannel() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareSelectFile(const std::vector<uint8_t>& lid) override;

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
    CardTransactionManager& prepareSelectFile(const SelectFileControl selectFileControl) override;

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
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadRecordFile(const uint8_t sfi,
                                                  const uint8_t firstRecordNumber,
                                                  const uint8_t numberOfRecords,
                                                  const uint8_t recordSize) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CardTransactionManager& prepareReadCounterFile(const uint8_t sfi, const uint8_t countersNumber)
        override;

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
                                                const std::vector<uint8_t>& recordData) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareUpdateRecord(const uint8_t sfi,
                                                const uint8_t recordNumber,
                                                const std::vector<uint8_t>& recordData) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareWriteRecord(const uint8_t sfi,
                                               const uint8_t recordNumber,
                                               const std::vector<uint8_t>& recordData) override;

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
                                                   const int incValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareDecreaseCounter(const uint8_t sfi,
                                                   const uint8_t counterNumber,
                                                   const int decValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareDecreaseCounters(
        const uint8_t sfi,
        const std::map<const int, const int>& counterNumberToDecValueMap) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CardTransactionManager& prepareIncreaseCounters(
        const uint8_t sfi,
        const std::map<const int, const int>& counterNumberToIncValueMap) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSetCounter(const uint8_t sfi,
                                              const uint8_t counterNumber,
                                              const int newValue) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareCheckPinStatus() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.
     */
    CardTransactionManager& prepareSvGet(const SvOperation svOperation, const SvAction svAction)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvReload(const int amount,
                                            const std::vector<uint8_t>& date,
                                            const std::vector<uint8_t>& time,
                                            const std::vector<uint8_t>& free) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvReload(const int amount) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvDebit(const int amount,
                                           const std::vector<uint8_t>& date,
                                           const std::vector<uint8_t>& time) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvDebit(const int amount) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareSvReadAllLogs() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareInvalidate() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardTransactionManager& prepareRehabilitate() override;

    /**
     * (private)<br>
     * Add a StoredValue command to the list.
     *
     * <p>Set up a mini state machine to manage the scheduling of Stored Value commands.
     *
     * <p>The {@link SvOperation} and {@link SvAction} are also used to check the consistency of the
     * SV process.
     *
     * <p>The svOperationPending flag is set when an SV operation (Reload/Debit/Undebit) command is
     * added.
     *
     * @param command the StoredValue command.
     * @param svOperation the type of the current SV operation (Reload/Debit/Undebit).
     * @throw IllegalStateException if the provided command is not an SV command or not properly
     *        used.
     */
    void addStoredValueCommand(const std::shared_ptr<AbstractCardCommand> command,
                               const SvOperation svOperation);

    /**
     * (private)<br>
     * Informs that the commands have been processed.
     *
     * <p>Just record the information. The initialization of the list of commands will be done only
     * the next time a command is added, this allows access to the commands contained in the list.
     */
    void notifyCommandsProcessed();

    /**
     * (private)<br>
     * Indicates whether an SV Operation has been completed (Reload/Debit/Undebit requested) <br>
     * This method is dedicated to triggering the signature verification after an SV transaction has
     * been executed. It is a single-use method, as the flag is systematically reset to false after it
     * is called.
     *
     * @return True if a "reload" or "debit" command has been requested
     */
    bool isSvOperationCompleteOneTime();

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
    static const std::string MSG_CARD_READER_COMMUNICATION_ERROR;
    static const std::string MSG_CARD_COMMUNICATION_ERROR;
    static const std::string MSG_CARD_COMMAND_ERROR;

    static const std::string MSG_PIN_NOT_AVAILABLE;
    static const std::string MSG_CARD_SIGNATURE_NOT_VERIFIABLE;
    static const std::string MSG_CARD_SIGNATURE_NOT_VERIFIABLE_SV;

    static const std::string RECORD_NUMBER;
    static const std::string OFFSET;

    /**
     * Commands that modify the content of the card in session have a cost on the session buffer
     * equal to the length of the outgoing data plus 6 bytes
     */
    static const int SESSION_BUFFER_CMD_ADDITIONAL_COST;
    static const int APDU_HEADER_LENGTH;

    /**
     *
     */
    static const std::shared_ptr<ApduResponseApi> RESPONSE_OK;
    static const std::shared_ptr<ApduResponseApi> RESPONSE_OK_POSTPONED;

    /**
     * Final fields
     */
    const std::shared_ptr<ProxyReaderApi> mCardReader;
    const std::shared_ptr<CalypsoCardAdapter> mCard;
    const std::shared_ptr<CardSecuritySettingAdapter> mSecuritySetting;
    std::shared_ptr<CardControlSamTransactionManagerAdapter> mControlSamTransactionManager;
    /**
     * C++: vector of AbstractApduCommand instead of AbstractCardCommand because of vector
     * vs. polymorphism issues...
     */
    std::vector<std::shared_ptr<AbstractApduCommand>> mCardCommands;

    /**
     * Dynamic fields
     */
    bool mIsSessionOpen = false;
    WriteAccessLevel mWriteAccessLevel = WriteAccessLevel::DEBIT; /* MSVC: default value required */
    ChannelControl mChannelControl = ChannelControl::KEEP_OPEN;
    int mModificationsCounter = 0;
    SvOperation mSvOperation;
    SvAction mSvAction = SvAction::DO; /* MSVC: default value required */
    CalypsoCardCommand mSvLastCommandRef = CalypsoCardCommand::NONE; /* GCC: default value required */
    std::shared_ptr<AbstractCardCommand> mSvLastModifyingCommand;
    bool mIsSvOperationInsideSession = false;
    bool mIsSvOperationComplete = false;

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
     *        C++: vector of AbstractApduCommand instead of AbstractCardCommand because of vector
     *        vs. polymorphism issues...
     * @param channelControl indicated if the card channel of the card reader must be closed after
     *        the last command.
     */
    void processAtomicCardCommands(
        const std::vector<std::shared_ptr<AbstractApduCommand>> cardCommands,
        const ChannelControl channelControl);

    /**
     * (private)<br>
     * Throws an exception if the multiple session is not enabled.
     *
     * @param command The command.
     * @throw SessionBufferOverflowException If the multiple session is not allowed.
     */
    void checkMultipleSessionEnabled(std::shared_ptr<AbstractCardCommand> command) const;

    /**
     * (private)<br>
     * Processes the "Card Cipher PIN" command on the control SAM.
     *
     * @param currentPin The current PIN.
     * @param newPin The new PIN, or null in case of a PIN presentation.
     * @return The cipher PIN data from the SAM (ciphered PIN transmission or PIN change).
     */
    const std::vector<uint8_t> processSamCardCipherPin(const std::vector<uint8_t>& currentPin,
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
     *        C++: vector of AbstractApduCommand instead of AbstractCardCommand because of vector
     *        vs. polymorphism issues...
     * @param isRatificationMechanismEnabled true if the ratification is closed not ratified and a
     *        ratification command must be sent.
     * @param channelControl indicates if the card channel of the card reader must be closed after
     *        the last command.
     */
    void processAtomicClosing(
        const std::vector<std::shared_ptr<AbstractApduCommand>>& cardCommands,
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
     *        C++: vector of AbstractApduCommand instead of AbstractCardCommand because of vector
     *        vs. polymorphism issues...
     * @return An empty list if there is no command.
     * @throw IllegalStateException if the anticipation process failed
     */
    const std::vector<std::shared_ptr<ApduResponseApi>> buildAnticipatedResponses(
        const std::vector<std::shared_ptr<AbstractApduCommand>>& cardCommands);

    /**
     * Process all prepared card commands (outside a Secure Session).
     *
     * <p>Note: commands prepared prior to the invocation of this method shall not require the use
     * of a SAM.
     *
     * @param channelControl indicates if the card channel of the card reader must be closed after
     *        the last command.
     */
    void processCommandsOutsideSession(const ChannelControl channelControl);

    /**
     * (private)<br>
     * Process all prepared card commands in a Secure Session.
     *
     * <p>The multiple session mode is handled according to the session settings.
     */
    void processCommandsInsideSession();

    /**
     * (private)<br>
     * Processes the "Card Generate Key" command on the control SAM.
     *
     * @param issuerKif The KIF of the key used for encryption.
     * @param issuerKvc The KVC of the key used for encryption.
     * @param newKif The KIF of the key to encrypt.
     * @param newKvc The KVC of the key to encrypt.
     * @return The value of the encrypted key.
     */
    const std::vector<uint8_t> processSamCardGenerateKey(const uint8_t issuerKif,
                                                         const uint8_t issuerKvc,
                                                         const uint8_t newKif,
                                                         const uint8_t newKvc);

    /**
     * (private)<br>
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @param channelControl The channel control.
     * @return The card response.
     */
    const std::shared_ptr<CardResponseApi> transmitCardRequest(
        const std::shared_ptr<CardRequestSpi> cardRequest, const ChannelControl channelControl);

    /**
     * Gets the terminal challenge from the SAM, and raises exceptions if necessary.
     * (private)<br>
     * Finalizes the last SV modifying command using the control SAM if an SV operation is pending.
     */
    void finalizeSvCommandIfNeeded();

    /**
     * (private)<br>
     * Processes the "SV Prepare Load" command on the control SAM.
     *
     * <p>Computes the cryptographic data required for the SvReload command.
     *
     * <p>Use the data from the SvGet command and the partial data from the SvReload command for this
     * purpose.
     *
     * <p>The returned data will be used to finalize the card SvReload command.
     *
     * @param svGetHeader the SV Get command header.
     * @param svGetData the SV Get command response data.
     * @param cmdCardSvReload the SvDebit command providing the SvReload partial data.
     * @return The complementary security data to finalize the SvReload card command (sam ID + SV
     *         prepare load output)
     */
    const std::vector<uint8_t> processSamSvPrepareLoad(
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData,
        const std::shared_ptr<CmdCardSvReload> cmdCardSvReload);

    /**
     * (private)<br>
     * Processes the "SV Prepare Debit/Undebit" command on the control SAM.
     *
     * <p>Computes the cryptographic data required for the SvDebit or SvUndebit command.
     *
     * <p>Use the data from the SvGet command and the partial data from the SvDebit command for this
     * purpose.
     *
     * <p>The returned data will be used to finalize the card SvDebit command.
     *
     * @param isDebitCommand True if the command is a DEBIT, false for UNDEBIT.
     * @param svGetHeader the SV Get command header.
     * @param svGetData the SV Get command response data.
     * @param cmdCardSvDebitOrUndebit The SvDebit or SvUndebit command providing the partial data.
     * @return The complementary security data to finalize the SvDebit/SvUndebit card command (sam ID
     *         + SV prepare debit/debit output)
     */
    const std::vector<uint8_t> processSamSvPrepareDebitOrUndebit(
        const bool isDebitCommand,
        const std::vector<uint8_t> svGetHeader,
        const std::vector<uint8_t> svGetData,
        const std::shared_ptr<CmdCardSvDebitOrUndebit> cmdCardSvDebitOrUndebit);

    /**
     * (private)<br>
     * Generic method to get the complementary data from SvPrepareLoad/Debit/Undebit commands
     *
     * <p>This data comprises:
     *
     * <ul>
     *   <li>The SAM identifier (4 bytes)
     *   <li>The SAM challenge (3 bytes)
     *   <li>The SAM transaction number (3 bytes)
     *   <li>The SAM part of the SV signature (5 or 10 bytes depending on card mode)
     * </ul>
     *
     * @param prepareOperationData the prepare operation output data.
     * @return a byte array containing the complementary data
     */
    const std::vector<uint8_t> computeOperationComplementaryData(
        const std::vector<uint8_t>& prepareOperationData);

    /**
     * (private)<br>
     * Processes the "SV Prepare Debit/Undebit" command on the control SAM.
     *
     * <p>Checks the status of the last SV operation.
     *
     * <p>The card signature is compared by the SAM with the one it has computed on its side.
     *
     * @param svOperationData The data of the SV operation performed.
     */
    void processSamSvCheck(const std::vector<uint8_t>& svOperationData);

    /**
     * (private)<br>
     * Processes the "Get Challenge" command on the control SAM.
     *
     * @return The SAM challenge.
     */
    const std::vector<uint8_t> processSamGetChallenge();

    /**
     * (private)<br>
     * Processes the pending session command including the "Digest Close" command on the control
     * SAM.
     *
     * @return The terminal signature from the SAM
     */
    const std::vector<uint8_t> processSamSessionClosing();

    /**
     * (private)<br>
     * Processes the "Digest Authenticate" command on the control SAM.
     *
     * @param cardSignature The card signature to check.
     */
    void processSamDigestAuthenticate(const std::vector<uint8_t>& cardSignature);

    /**
     * (private)<br>
     * Checks if a Secure Session is open, raises an exception if not
     *
     * @throw IllegalStateException if no session is open
     */
    void checkSession();

    /**
     * (private)<br>
     * Checks if a Secure Session is not open, raises an exception if not
     *
     * @throw IllegalStateException if a session is open
     */
    void checkNoSession();

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
     * (private)<br>
     * Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
     */
    CardTransactionManager& prepareIncreaseOrDecreaseCounter(const bool isDecreaseCommand,
                                                             const uint8_t sfi,
                                                             const uint8_t counterNumber,
                                                             const int incDecValue);

    /**
     * (private)<br>
     * Factorisation of prepareDecreaseMultipleCounters and prepareIncreaseMultipleCounters.
     */
    CardTransactionManager& prepareIncreaseOrDecreaseCounters(
        const bool isDecreaseCommand,
        const uint8_t sfi,
        const std::map<const int, const int>& counterNumberToIncDecValueMap);



    /**
     * (private)<br>
     * Checks if the control SAM is set.
     *
     * @throw IllegalStateException If control SAM is not set.
     */
    void checkControlSam() const;

    /**
     * (private)<br>
     * Process the eventually prepared SAM commands if control SAM is set.
     */
    void processSamPreparedCommands();

    /**
     * (private)<br>
     * Open a single Secure Session.
     *
     * @param cardCommands the card commands inside session.
     *        C++: vector of AbstractApduCommand instead of AbstractCardCommand because of vector
     *        vs. polymorphism issues...
     * @throw IllegalStateException if no CardSecuritySetting is available.
     */
    void processAtomicOpening(std::vector<std::shared_ptr<AbstractApduCommand>>& cardCommands);

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
     * CL-CSS-OSSMODE.1<br>
     * CL-SV-CMDMODE.1
     *
     * @return True if the card extended mode is allowed.
     */
    bool isExtendedModeAllowed() const;

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
