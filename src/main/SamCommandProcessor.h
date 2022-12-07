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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Calypsonet Terminal Card */
#include "ProxyReaderApi.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "CalypsoCardAdapter.h"
#include "CardSecuritySettingAdapter.h"
#include "CmdCardSvDebitOrUndebit.h"
#include "CmdCardSvReload.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::sam;
using namespace calypsonet::terminal::card;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * The SamCommandProcessor class is dedicated to the management of commands sent to the SAM.
 *
 * <p>In particular, it manages the cryptographic computations related to the secure session (digest
 * computation).
 *
 * <p>It also will integrate the SAM commands used for Stored Value and PIN/key management. In
 * session, these commands need to be carefully synchronized with the digest calculation.
 *
 * @since 2.0.0
 */
class SamCommandProcessor {
public:
    /**
     * Constructor
     *
     * @param card The initial card data provided by the selection process.
     * @param securitySetting The security settings from the application layer.
     * @param transactionAuditData The transaction audit data list to fill.
     * @since 2.0.0
     */
    SamCommandProcessor(const std::shared_ptr<CalypsoCardAdapter> card,
                        const std::shared_ptr<CardSecuritySettingAdapter> securitySetting,
                        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * Gets the SAM challenge
     *
     * <p>Performs key diversification if necessary by sending the SAM Select Diversifier command
     * prior to the Get Challenge command. The diversification flag is set to avoid further
     * unnecessary diversification operations.
     *
     * <p>If the key diversification is already done, the Select Diversifier command is omitted.
     *
     * <p>The length of the challenge varies from one card product type to another. This information
     * can be found in the CardResource class field.
     *
     * @return the terminal challenge as an array of bytes
     * @throw CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @throw InconsistentDataException if the APDU SAM exchanges are out of sync
     * @since 2.0.0
     */
    const std::vector<uint8_t> getChallenge();

    /**
     * (package-private)<br>
     * Gets the KVC to use according to the provided write access and the card's KVC.
     *
     * @param writeAccessLevel The write access level.
     * @param kvc The card KVC value.
     * @return Null if the card did not provide a KVC value and if there's no default KVC value.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> computeKvc(const WriteAccessLevel writeAccessLevel,
                                              const std::shared_ptr<uint8_t> kvc) const;

    /**
     * (package-private)<br>
     * Gets the KIF to use according to the provided write access level and KVC.
     *
     * @param writeAccessLevel The write access level.
     * @param kif The card KIF value.
     * @param kvc The previously computed KVC value.
     * @return Null if the card did not provide a KIF value and if there's no default KIF value.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> computeKif(const WriteAccessLevel writeAccessLevel,
                                              const std::shared_ptr<uint8_t> kif,
                                              const std::shared_ptr<uint8_t> kvc);

    /**
     * Initializes the digest computation process
     *
     * <p>Resets the digest data cache, then fills a first packet with the provided data (from open
     * secure session).
     *
     * <p>Keeps the session parameters, sets the KIF if not defined
     *
     * <p>Note: there is no communication with the SAM here.
     *
     * @param isSessionEncrypted true if the session is encrypted.
     * @param isVerificationMode true if the verification mode is active.
     * @param kif the KIF.
     * @param kvc the KVC.
     * @param digestData a first packet of data to digest.
     * @since 2.0.0
     */
    void initializeDigester(const bool isSessionEncrypted,
                            const bool isVerificationMode,
                            const uint8_t kif,
                            const uint8_t kvc,
                            const std::vector<uint8_t>& digestData);

    /**
     * Appends a list full card exchange (request and response) to the digest data cache.<br>
     * The startIndex argument makes it possible not to include the beginning of the list when
     * necessary.
     *
     * @param requests card request list.
     * @param responses card response list.
     * @param startIndex starting point in the list.
     * @since 2.0.0
     */
    void pushCardExchangedData(const std::vector<std::shared_ptr<ApduRequestSpi>>& requests,
                               const std::vector<std::shared_ptr<ApduResponseApi>>& responses,
                               const int startIndex);

    /**
     * (package-private)<br>
     * Gets the terminal signature's high part from the SAM
     *
     * <p>All remaining data in the digest cache is sent to the SAM and the Digest Close command is
     * executed.
     *
     * @return The terminal signature's high part.
     * @throws CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @throw InconsistentDataException if the APDU SAM exchanges are out of sync.
     * @since 2.0.0
     */
    const std::vector<uint8_t> getTerminalSignature();

    /**
     * (private)<br>
     * Transmits the provided commands to the SAM, then attach responses and check status words.
     *
     * @param samCommands The SAM commands.
     * @throw ReaderBrokenCommunicationException If the communication with the SAM reader has failed.
     * @throw CardBrokenCommunicationException If the communication with the SAM has failed.
     * @throw CalypsoSamCommandException If the SAM has responded with an error status.
     * @throw InconsistentDataException If the APDU SAM exchanges are out of sync.
     */
    void transmitCommands(const std::vector<std::shared_ptr<AbstractSamCommand>>& samCommands);

    /**
     * Authenticates the signature part from the card
     *
     * <p>Executes the Digest Authenticate command with the card part of the signature.
     *
     * @param cardSignatureLo the card part of the signature.
     * @throws CalypsoSamCommandException if the SAM has responded with an error status
     * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
     * @throws InconsistentDataException if the APDU SAM exchanges are out of sync
     * @since 2.0.0
     */
    void authenticateCardSignature(const std::vector<uint8_t>& cardSignatureLo);

    /**
     * (package-private)<br>
     * Compute the encrypted key data for the "Change Key" command.
     *
     * @param cardChallenge The challenge from the card.
     * @param cipheringKif The KIF of the key used for encryption.
     * @param cipheringKvc The KVC of the key used for encryption.
     * @param sourceKif The KIF of the key to encrypt.
     * @param sourceKvc The KVC of the key to encrypt.
     * @return An array of 32 bytes containing the encrypted key.
     * @throw CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @since 2.1.0
     */
    const std::vector<uint8_t> getEncryptedKey(const std::vector<uint8_t>& cardChallenge,
                                               const uint8_t cipheringKif,
                                               const uint8_t cipheringKvc,
                                               const uint8_t sourceKif,
                                               const uint8_t sourceKvc);

    /**
     * (package-private)<br>
     * Compute the PIN ciphered data for the encrypted PIN verification or PIN update commands
     *
     * @param cardChallenge the challenge from the card.
     * @param currentPin the current PIN value.
     * @param newPin the new PIN value (set to null if the operation is a PIN presentation).
     * @return the PIN ciphered data
     * @throw CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @since 2.0.0
     */
    const std::vector<uint8_t> getCipheredPinData(const std::vector<uint8_t>& cardChallenge,
                                                  const std::vector<uint8_t>& currentPin,
                                                  const std::vector<uint8_t>& newPin);

    /**
     * Computes the cryptographic data required for the SvReload command.
     *
     * <p>Use the data from the SvGet command and the partial data from the SvReload command for this
     * purpose.
     *
     * <p>The returned data will be used to finalize the card SvReload command.
     *
     * @param cmdCardSvReload the SvDebit command providing the SvReload partial data.
     * @param svGetHeader the SV Get command header.
     * @param svGetData the SV Get command response data.
     * @return the complementary security data to finalize the SvReload card command (sam ID + SV
     *     prepare load output)
     * @throw CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @since 2.0.0
     */
    const std::vector<uint8_t> getSvReloadComplementaryData(
        const std::shared_ptr<CmdCardSvReload> cmdCardSvReload,
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData);

    /**
     * (package-private)<br>
     * Computes the cryptographic data required for the SvDebit command.
     *
     * <p>Use the data from the SvGet command and the partial data from the SvDebit or SvUndebit
     * command for this purpose.
     *
     * <p>The returned data will be used to finalize the card SvDebit command.
     *
     * @param isDebitCommand True if the command is a DEBIT, false for UNDEBIT.
     * @param svGetHeader the SV Get command header.
     * @param svGetData the SV Get command response data.
     * @return the complementary security data to finalize the SvDebit/SvUndebit card command (sam
     *     ID + SV prepare load output)
     * @throws CalypsoSamCommandException if the SAM has responded with an error status
     * @throws ReaderBrokenCommunicationException if the communication with the SAM reader has failed.
     * @throws CardBrokenCommunicationException if the communication with the SAM has failed.
     * @since 2.0.0
     */
    const std::vector<uint8_t> getSvDebitOrUndebitComplementaryData(
        const bool isDebitCommand,
        const std::shared_ptr<CmdCardSvDebitOrUndebit> cmdCardSvDebitOrUndebit,
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData);

    /**
     * Checks the status of the last SV operation
     *
     * <p>The card signature is compared by the SAM with the one it has computed on its side.
     *
     * @param svOperationResponseData the data of the SV operation performed.
     * @throw CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has
     *        failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @since 2.0.0
     */
    void checkSvStatus(const std::vector<uint8_t>& svOperationResponseData);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(SamCommandProcessor));

    /**
     *
     */
    static const uint8_t KIF_UNDEFINED;
    static const uint8_t CHALLENGE_LENGTH_REV_INF_32;
    static const uint8_t CHALLENGE_LENGTH_REV32;
    static const uint8_t SIGNATURE_LENGTH_REV_INF_32;
    static const uint8_t SIGNATURE_LENGTH_REV32;
    static const std::string UNEXPECTED_EXCEPTION;

    /**
     */
    std::shared_ptr<ProxyReaderApi> mSamReader;

    /**
     *
     */
    const std::shared_ptr<CardSecuritySettingAdapter> mSecuritySetting;

    /**
     *
     */
    static std::vector<std::vector<uint8_t>> mCardDigestDataCache;

    /**
     *
     */
    const std::shared_ptr<CalypsoCardAdapter> mCard;

    /**
     *
     */
    std::vector<uint8_t> mSamSerialNumber;

    /**
     *
     */
    CalypsoSam::ProductType mSamProductType;

    /**
     *
     */
    bool mIsSessionEncrypted;

    /**
     *
     */
    bool mIsVerificationMode;

    /**
     *
     */
    uint8_t mKif;

    /**
     *
     */
    uint8_t mKvc;

    /**
     *
     */
    bool mIsDiversificationDone;

    /**
     *
     */
    bool mIsDigestInitDone;

    /**
     *
     */
    bool mIsDigesterInitialized;

    /**
     * 
     */
    std::vector<std::vector<uint8_t>> mTransactionAuditData;

     /**
     * Appends a full card exchange (request and response) to the digest data cache.
     *
     * @param request card request.
     * @param response card response.
     * @since 2.0.0
     */
    void pushCardExchangedData(const std::shared_ptr<ApduRequestSpi> request,
                               const std::shared_ptr<ApduResponseApi> response);

    /**
     * Gets a single SAM request for all prepared SAM commands.
     *
     * <p>Builds all pending SAM commands related to the digest calculation process of a secure
     * session
     *
     * <ul>
     *   <li>Starts with a Digest Init command if not already done,
     *   <li>Adds as many Digest Update commands as there are packages in the cache,
     *   <li>Appends a Digest Close command if the addDigestClose flag is set to true.
     * </ul>
     *
     * @param addDigestClose indicates whether to add the Digest Close command.
     * @return a list of commands to send to the SAM
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<AbstractSamCommand>> getPendingSamCommands(
        const bool addDigestClose);

    /**
     * Create an ApduRequestAdapter List from a AbstractSamCommand List.
     *
     * @param samCommands a list of SAM commands.
     * @return the ApduRequestAdapter list
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<ApduRequestSpi>> getApduRequests(
        const std::vector<std::shared_ptr<AbstractSamCommand>> samCommands) const;

    /**
     * Generic method to get the complementary data from SvPrepareLoad/Debit/Undebit commands
     *
     * <p>Executes the SV Prepare SAM command to prepare the data needed to complete the card SV
     * command.
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
     * @param cmdSamSvPrepare the prepare command (can be prepareSvReload/Debit/Undebit).
     * @return a byte array containing the complementary data
     * @throw CalypsoSamCommandException if the SAM has responded with an error status
     * @throw ReaderBrokenCommunicationException if the communication with the SAM reader has
     *        failed.
     * @throw CardBrokenCommunicationException if the communication with the SAM has failed.
     * @since 2.0.0
     */
    const std::vector<uint8_t> getSvComplementaryData(
        const std::shared_ptr<AbstractSamCommand> cmdSamSvPrepare);
};

}
}
}
