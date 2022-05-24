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

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardClass.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Open Secure Session APDU command.
 *
 * @since 2.0.1
 */
class CmdCardOpenSession final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardOpenSession.
     *
     * @param calypsoCard the {@link CalypsoCard}.
     * @throws IllegalArgumentException If the key index is 0 and rev is 2.4
     * @throws IllegalArgumentException If the request is inconsistent
     * @since 2.0.1
     */
    CmdCardOpenSession(const std::shared_ptr<CalypsoCard> calypsoCard,
                       const uint8_t debitKeyIndex,
                       const std::vector<uint8_t> sessionTerminalChallenge,
                       const int sfi,
                       const int recordNumber);

    /**
     * (private)<br>
     * Create Rev 3
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to read.
     * @param calypsoCard The {@link CalypsoCard}.
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void createRev3(const uint8_t keyIndex,
                    const std::vector<uint8_t>& samChallenge,
                    const int sfi,
                    const int recordNumber,
                    const std::shared_ptr<CalypsoCard> calypsoCard);

    /**
     * (private)<br>
     * Create Rev 2.4
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to read.
     * @throw IllegalArgumentException If key index is 0 (rev 2.4)
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void createRev24(const uint8_t keyIndex,
                     const std::vector<uint8_t>& samChallenge,
                     const int sfi,
                     const int recordNumber);

    /**
     * (private)<br>
     * Create Rev 1.0
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to read.
     * @throw IllegalArgumentException If key index is 0 (rev 1.0)
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void createRev10(const uint8_t keyIndex,
                     const std::vector<uint8_t>& samChallenge,
                     const int sfi,
                     const int recordNumber);

    /**
     * (private)<br>
     * Build legacy apdu request.
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge APDU command.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to read.
     * @param p1 P1.
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void buildLegacyApduRequest(const uint8_t keyIndex,
                                const std::vector<uint8_t>& samChallenge,
                                const int sfi,
                                const int recordNumber,
                                const uint8_t p1) ;

    /**
     * {@inheritDoc}
     *
     * @return False
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     *
     * @return the SFI of the file read while opening the secure session
     * @since 2.0.1
     */
    int getSfi() const;

    /**
     * (package-private)<br>
     *
     * @return the record number to read
     * @since 2.0.1
     */
    int getRecordNumber() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    CmdCardOpenSession& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
        override;

    /**
     * (private)<br>
     * Parse Rev 3
     *
     * @param apduResponseData The response data.
     */
    void parseRev3(const std::vector<uint8_t>& apduResponseData);

    /**
     * (private)<br>
     * Parse Rev 2.4
     *
     * <p>In rev 2.4 mode, the response to the Open Secure Session command is as follows:
     *
     * <p><code>KK CC CC CC CC [RR RR] [NN..NN]</code>
     *
     * <p>Where:
     *
     * <ul>
     *   <li><code>KK</code> = KVC byte CC
     *   <li><code>CC CC CC CC</code> = card challenge
     *   <li><code>RR RR</code> = ratification bytes (may be absent)
     *   <li><code>NN..NN</code> = record data (29 bytes)
     * </ul>
     *
     * Legal length values are:
     *
     * <ul>
     *   <li>5: ratified, 1-byte KCV, 4-byte challenge, no data
     *   <li>34: ratified, 1-byte KCV, 4-byte challenge, 29 bytes of data
     *   <li>7: not ratified (2 ratification bytes), 1-byte KCV, 4-byte challenge, no data
     *   <li>35 not ratified (2 ratification bytes), 1-byte KCV, 4-byte challenge, 29 bytes of data
     * </ul>
     *
     * @param apduResponseData The response data.
     */
    void parseRev24(const std::vector<uint8_t>& apduResponseData);

    /**
     * (private)<br>
     * Parse Rev 1.0
     *
     * <p>In rev 1.0 mode, the response to the Open Secure Session command is as follows:
     *
     * <p><code>CC CC CC CC [RR RR] [NN..NN]</code>
     *
     * <p>Where:
     *
     * <ul>
     *   <li><code>CC CC CC CC</code> = card challenge
     *   <li><code>RR RR</code> = ratification bytes (may be absent)
     *   <li><code>NN..NN</code> = record data (29 bytes)
     * </ul>
     *
     * Legal length values are:
     *
     * <ul>
     *   <li>4: ratified, 4-byte challenge, no data
     *   <li>33: ratified, 4-byte challenge, 29 bytes of data
     *   <li>6: not ratified (2 ratification bytes), 4-byte challenge, no data
     *   <li>35 not ratified (2 ratification bytes), 4-byte challenge, 29 bytes of data
     * </ul>
     *
     * @param apduResponseData The response data.
     */
    void parseRev10(const std::vector<uint8_t>& apduResponseData);

    /**
     * (package-private)<br>
     *
     * @return A non empty value.
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getCardChallenge() const;

    /**
     * (package-private)<br>
     *
     * @return A non negative number.
     * @since 2.0.1
     */
    int getTransactionCounterValue() const;

    /**
     * (package-private)<br>
     *
     * @return True if the previous session was ratified.
     * @since 2.0.1
     */
    bool wasRatified() const;

    /**
     * (package-private)<br>
     *
     * @return True if the managed secure session is authorized.
     * @since 2.0.1
     */
    bool isManageSecureSessionAuthorized() const;

    /**
     * (package-private)<br>
     *
     * @return The current KIF.
     * @since 2.0.1
     */
    const std::shared_ptr<uint8_t> getSelectedKif() const;

    /**
     * (package-private)<br>
     *
     * @return The current KVC.
     * @since 2.0.1
     */
    const std::shared_ptr<uint8_t> getSelectedKvc() const;

    /**
     * (package-private)<br>
     *
     * @return The optional read data.
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getRecordDataRead() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     * (private)<br>
     * The Class SecureSession.
     */
    class SecureSession {
    public:
        /**
         *
         */
        friend class CmdCardOpenSession;

        /**
         *
         */
        const std::vector<uint8_t>& getChallengeTransactionCounter() const;

        /**
         *
         */
        const std::vector<uint8_t>& getChallengeRandomNumber() const;

        /**
         * Checks if is previous session ratified.
         *
         * @return The boolean
         * @since 2.0.1
         */
        bool isPreviousSessionRatified() const;

        /**
         * Checks if is manage secure session authorized.
         *
         * @return True if the secure session is authorized
         * @since 2.0.1
         */
        bool isManageSecureSessionAuthorized() const;

        /**
         * Gets the kif.
         *
         * @return A byte
         * @since 2.0.1
         */
        const std::shared_ptr<uint8_t> getKIF() const;

        /**
         * Gets the kvc.
         *
         * @return A byte
         * @since 2.0.1
         */
        const std::shared_ptr<uint8_t> getKVC() const;

        /**
         * Gets the original data.
         *
         * @return An array of bytes
         * @since 2.0.1
         */
        const std::vector<uint8_t>& getOriginalData() const;

        /**
         * Gets the secure session data.
         *
         * @return An array of bytes
         * @since 2.0.1
         */
        const std::vector<uint8_t>& getSecureSessionData() const;

    private:
        /**
         * Challenge transaction counter
         */
        const std::vector<uint8_t> mChallengeTransactionCounter;

        /**
         * Challenge random number
         */
        const std::vector<uint8_t> mChallengeRandomNumber;

        /**
         * The previous session ratified boolean
         */
        const bool mPreviousSessionRatified;

        /**
         * The manage secure session authorized boolean
         */
        const bool mManageSecureSessionAuthorized;

        /**
         * The kif (it may be null if it doesn't exist in the considered card [rev 1.0])
         */
        const std::shared_ptr<uint8_t> mKif;

        /**
         * The kvc (it may be null if it doesn't exist in the considered card [rev 1.0])
         */
        const std::shared_ptr<uint8_t> mKvc;

        /**
         * The original data
         */
        const std::vector<uint8_t> mOriginalData;

        /**
         * The secure session data
         */
        const std::vector<uint8_t> mSecureSessionData;

        /**
         * Instantiates a new SecureSession
         *
         * @param challengeTransactionCounter Challenge transaction counter.
         * @param challengeRandomNumber Challenge random number.
         * @param previousSessionRatified the previous session ratified.
         * @param manageSecureSessionAuthorized the manage secure session authorized.
         * @param kif the KIF from the response of the open secure session APDU command.
         * @param kvc the KVC from the response of the open secure session APDU command.
         * @param originalData the original data from the response of the open secure session APDU.
         *        command
         * @param secureSessionData the secure session data from the response of open secure session.
         *        APDU command
         * @since 2.0.1
         */
        SecureSession(const std::vector<uint8_t>& challengeTransactionCounter,
                      const std::vector<uint8_t>& challengeRandomNumber,
                      const bool previousSessionRatified,
                      const bool manageSecureSessionAuthorized,
                      const std::shared_ptr<uint8_t> kif,
                      const std::shared_ptr<uint8_t> kvc,
                      const std::vector<uint8_t>& originalData,
                      const std::vector<uint8_t>& secureSessionData);
    };

    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CmdCardOpenSession));

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const std::shared_ptr<CalypsoCard> mCalypsoCard;

    /**
     *
     */
    int mSfi;

    /**
     *
     */
    int mRecordNumber;

    /**
     * The secure session
     */
    std::shared_ptr<SecureSession> mSecureSession;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
