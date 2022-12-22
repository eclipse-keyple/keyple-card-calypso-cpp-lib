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

/* Calypsonet Terminal Calypso */
#include "WriteAccessLevel.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CardSecuritySettingAdapter.h"
#include "CmdSamCardCipherPin.h"
#include "CmdSamCardGenerateKey.h"
#include "CmdSamDigestClose.h"
#include "CmdSamGetChallenge.h"
#include "CmdSamSvPrepareDebitOrUndebit.h"
#include "CmdSamSvPrepareLoad.h"
#include "CmdCardSvReload.h"
#include "CmdCardSvDebitOrUndebit.h"
#include "CommonControlSamTransactionManagerAdapter.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Card Control SAM Transaction Manager.
 *
 * @since 2.2.0
 */
class CardControlSamTransactionManagerAdapter final
: public CommonControlSamTransactionManagerAdapter<CardSecuritySettingAdapter> {
public:
    /**
     * (package-private)<br>
     * Creates a new instance to control a card.
     *
     * @param targetCard The target card to control provided by the selection process.
     * @param securitySetting The associated card security settings.
     * @param transactionAuditData The original transaction data to fill.
     * @since 2.2.0
     */
    CardControlSamTransactionManagerAdapter(
        const std::shared_ptr<CalypsoCardAdapter> targetCard,
        const std::shared_ptr<CardSecuritySettingAdapter> securitySetting,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * (package-private)<br>
     * Returns the KVC to use according to the provided write access and the card's KVC.
     *
     * @param writeAccessLevel The write access level.
     * @param kvc The card KVC value.
     * @return Null if the card did not provide a KVC value and if there's no default KVC value.
     * @since 2.2.0
     */
    std::shared_ptr<uint8_t> computeKvc(const WriteAccessLevel writeAccessLevel,
                                        const std::shared_ptr<uint8_t> kvc) const;

    /**
     * (package-private)<br>
     * Returns the KIF to use according to the provided write access level and KVC.
     *
     * @param writeAccessLevel The write access level.
     * @param kif The card KIF value.
     * @param kvc The previously computed KVC value.
     * @return Null if the card did not provide a KIF value and if there's no default KIF value.
     * @since 2.2.0
     */
    std::shared_ptr<uint8_t> computeKif(const WriteAccessLevel writeAccessLevel,
                                        const std::shared_ptr<uint8_t> kif,
                                        const std::shared_ptr<uint8_t> kvc) const;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& processCommands() override;

    /**
     * (package-private)<br>
     * Prepares a "Get Challenge" SAM command.
     *
     * @return The reference to the prepared command.
     * @since 2.2.0
     */
    std::shared_ptr<CmdSamGetChallenge> prepareGetChallenge();

    /**
     * (package-private)<br>
     * Prepares a "Give Random" SAM command.
     *
     * @since 2.2.0
     */
    void prepareGiveRandom();

    /**
     * (package-private)<br>
     * Prepares a "Card Generate Key" SAM command.
     *
     * @param cipheringKif The KIF of the key used for encryption.
     * @param cipheringKvc The KVC of the key used for encryption.
     * @param sourceKif The KIF of the key to encrypt.
     * @param sourceKvc The KVC of the key to encrypt.
     * @return The reference to the prepared command.
     * @since 2.2.0
     */
    const std::shared_ptr<CmdSamCardGenerateKey> prepareCardGenerateKey(
        const uint8_t cipheringKif,
        const uint8_t cipheringKvc,
        const uint8_t sourceKif,
        const uint8_t sourceKvc);

    /**
     * (package-private)<br>
     * Prepares a "Card Cipher Pin" SAM command.
     *
     * @param currentPin the current PIN value.
     * @param newPin the new PIN value (set to null if the operation is a PIN presentation).
     * @return The reference to the prepared command.
     * @since 2.2.0
     */
    const std::shared_ptr<CmdSamCardCipherPin> prepareCardCipherPin(
        const std::vector<uint8_t>& currentPin,
        const std::vector<uint8_t>& newPin);

    /**
     * (package-private)<br>
     * Prepares a "SV Prepare Load" SAM command.
     *
     * @param svGetHeader The SV Get command header.
     * @param svGetData The SV Get command response data.
     * @param cmdCardSvReload The SvDebit command providing the SvReload partial data.
     * @return The reference to the prepared command.
     * @since 2.2.0
     */
    const std::shared_ptr<CmdSamSvPrepareLoad> prepareSvPrepareLoad(
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData,
        const std::shared_ptr<CmdCardSvReload> cmdCardSvReload);

    /**
     * (package-private)<br>
     * Prepares a "SV Prepare Debit/Undebit" SAM command.
     *
     * @param isDebitCommand True if the command is a DEBIT, false for UNDEBIT.
     * @param svGetHeader the SV Get command header.
     * @param svGetData the SV Get command response data.
     * @param cmdCardSvDebitOrUndebit The SvDebit or SvUndebit command providing the partial data.
     * @return The reference to the prepared command.
     * @since 2.2.0
     */
    const std::shared_ptr<CmdSamSvPrepareDebitOrUndebit> prepareSvPrepareDebitOrUndebit(
        const bool isDebitCommand,
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData,
        const std::shared_ptr<CmdCardSvDebitOrUndebit> cmdCardSvDebitOrUndebit);

    /**
     * (package-private)<br>
     * Prepares a "SV Check" SAM command.
     *
     * @param svOperationData The data of the SV operation performed.
     * @since 2.2.0
     */
    void prepareSvCheck(const std::vector<uint8_t>& svOperationData);

    /**
     * (package-private)<br>
     * Opens a new session by initializing the digest manager. It will store all digest operations
     * (Digest Init, Digest Update) until the session closing. At this moment, all SAM Apdu will be
     * processed at once.
     *
     * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
     * @param kif The KIF to use.
     * @param kvc The KVC to use.
     * @param isSessionEncrypted True if the session is encrypted.
     * @param isVerificationMode True if the verification mode is enabled.
     * @since 2.2.0
     */
    void initializeSession(
        const std::vector<uint8_t>& openSecureSessionDataOut,
        const uint8_t kif,
        const uint8_t kvc,
        const bool isSessionEncrypted,
        const bool isVerificationMode);

    /**
     * (package-private)<br>
     * Updates the session with the exchanged card APDUs.
     *
     * @param requests The card requests.
     * @param responses The associated card responses.
     * @param startIndex The index of the request from which to start.
     * @since 2.2.0
     */
    void updateSession(const std::vector<std::shared_ptr<ApduRequestSpi>>& requests,
                       const std::vector<std::shared_ptr<ApduResponseApi>>& responses,
                       const int startIndex);

    /**
     * (package-private)<br>
     * Prepares all pending digest commands in order to close the session.
     *
     * @return The reference to the prepared "Digest Close" SAM command.
     * @since 2.2.0
     */
    const std::shared_ptr<CmdSamDigestClose> prepareSessionClosing();

    /**
     * (package-private)<br>
     * Prepares a "Digest Authenticate" SAM command.
     *
     * @param cardSignatureLo The card signature LO part.
     * @since 2.2.0
     */
    void prepareDigestAuthenticate(const std::vector<uint8_t>& cardSignatureLo);

private:
    /**
     * (private)<br>
     * The manager of the digest session.
     */
    class DigestManager {
    public:
        /**
         *
         */
        const uint8_t mSessionKif;

        /**
         *
         */
        const uint8_t mSessionKvc;

        /**
         *
         */
        bool mIsDigestInitDone = false;

        /**
         *
         */
        const std::vector<uint8_t> mOpenSecureSessionDataOut;

        /**
         *
         */
        const bool mIsSessionEncrypted;

        /**
         *
         */
        const bool mIsVerificationMode;

        /**
         *
         */
        std::vector<std::vector<uint8_t>> mCardApdus;

        /**
         *
         */
        CardControlSamTransactionManagerAdapter *mParent;

        /**
         * (private)<br>
         * Creates a new digest manager.
         *
         * @param openSecureSessionDataOut The data out of the "Open Secure Session" card command.
         * @param kif The KIF to use.
         * @param kvc The KVC to use.
         * @param isSessionEncrypted True if the session is encrypted.
         * @param isVerificationMode True if the verification mode is enabled.
         */
        DigestManager(CardControlSamTransactionManagerAdapter* parent,
                      const std::vector<uint8_t>& openSecureSessionDataOut,
                      const uint8_t kif,
                      const uint8_t kvc,
                      const bool isSessionEncrypted,
                      const bool isVerificationMode);

        /**
         * (private)<br>
         * Add one or more exchanged card APDUs to the buffer.
         *
         * @param requests The requests.
         * @param responses The associated responses.
         * @param startIndex The index of the request from which to start.
         */
        void updateSession(const std::vector<std::shared_ptr<ApduRequestSpi>>& requests,
                           const std::vector<std::shared_ptr<ApduResponseApi>>& responses,
                           const int startIndex);

        /**
         * (private)<br>
         * Prepares all pending digest commands.
         */
        void prepareCommands();

        /**
         * (private)<br>
         * Prepares the "Digest Init" SAM command.
         */
        void prepareDigestInit();

        /**
         * (private)<br>
         * Prepares the "Digest Update" SAM command.
         */
        void prepareDigestUpdate();

        /**
         * (private)<br>
         * Prepares the "Digest Close" SAM command.
         */
        void prepareDigestClose();
    };

    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CardControlSamTransactionManagerAdapter));

    /**
     *
     */
    const std::shared_ptr<CalypsoSamAdapter> mControlSam = nullptr;

    /**
     *
     */
    const std::shared_ptr<CalypsoCardAdapter> mTargetCard;

    /**
     *
     */
    const std::shared_ptr<CardSecuritySettingAdapter> mCardSecuritySetting;

    /**
     *
     */
    std::shared_ptr<DigestManager> mDigestManager;
};

}
}
}

