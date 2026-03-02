/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/card/calypso/SymmetricCryptoSecuritySettingAdapter.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

/**
 * Builds the Open Secure Session APDU command.
 *
 * @since 2.0.1
 */
class CommandOpenSecureSession final : public Command {
public:
    /**
     * Constructor for "pre-open" variant (to be used for card selection only).
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param writeAccessLevel The write access level.
     * @since 2.3.3
     */
    CommandOpenSecureSession(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        WriteAccessLevel writeAccessLevel);

    /**
     * Partial constructor.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param symmetricCryptoSecuritySetting The symmetric crypto security
     * settings to use.
     * @param writeAccessLevel The write access level.
     * @param isExtendedModeAllowed Is the extended mode allowed?
     * @since 2.3.2
     */
    CommandOpenSecureSession(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
            symmetricCryptoSecuritySetting,
        WriteAccessLevel writeAccessLevel,
        bool isExtendedModeAllowed);

    /**
     * Constructor for PKI mode variant.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param terminalChallenge The terminal challenge.
     * @since 3.1.0
     */
    CommandOpenSecureSession(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        const std::vector<std::uint8_t>& terminalChallenge);

    /**
     * Configures the read mode.
     *
     * @param sfi The SFI to select.
     * @param recordNumber The number of the record to read.
     * @param expectedRecordDataLength The expected record data length.
     * @since 2.3.2
     */
    void
    configureReadMode(int sfi, int recordNumber, int expectedRecordDataLength);

    /**
     * @return "true" if the read mode is already configured.
     * @since 2.3.2
     */
    bool isReadModeConfigured() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool isCryptoServiceRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool synchronizeCryptoServiceBeforeCardProcessing() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandOpenSecureSession));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /** */
    static const std::string PATTERN_1_BYTE_HEX;

    /** */
    WriteAccessLevel mWriteAccessLevel;

    /** */
    bool mIsExtendedModeAllowed;

    /** */
    std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
        mSymmetricCryptoSecuritySetting;

    /** */
    bool mIsPreOpenModeOnSelection;

    /** */
    bool mIsPreOpenMode;

    /** */
    std::vector<std::uint8_t> mPreOpenDataOut;

    /** */
    bool mIsReadModeConfigured = false;

    /** */
    int mSfi = 0;

    /** */
    int mRecordNumber = 0;

    /** */
    bool mIsPreviousSessionRatified;

    /** */
    std::vector<std::uint8_t> mChallengeTransactionCounter;

    /** */
    std::shared_ptr<std::uint8_t> mKif;

    /** */
    std::shared_ptr<std::uint8_t> mKvc;

    /** */
    std::vector<std::uint8_t> mRecordData;

    /** */
    int mExpectedRecordDataLength = 0;

    /**
     * Create Rev 3
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge
     * APDU command.
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void createRev3(
        std::uint8_t keyIndex, const std::vector<std::uint8_t>& samChallenge);

    /**
     * Create Rev 2.4
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge
     * APDU command.
     */
    void createRev24(
        std::uint8_t keyIndex, const std::vector<std::uint8_t>& samChallenge);

    /**
     * Create Rev 1.0
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge
     * APDU command.
     */
    void createRev10(
        std::uint8_t keyIndex, const std::vector<std::uint8_t>& samChallenge);

    /**
     * Create Rev 3 for PKI mode
     *
     * @param terminalChallenge the terminal challenge.
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void createRev3Pki(const std::vector<std::uint8_t>& terminalChallenge);

    /**
     * Build legacy apdu request.
     *
     * @param keyIndex the key index.
     * @param samChallenge the sam challenge returned by the SAM Get Challenge
     * APDU command.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to read.
     * @param p1 P1.
     * @throw IllegalArgumentException If the request is inconsistent
     */
    void buildLegacyApduRequest(
        std::uint8_t keyIndex,
        const std::vector<std::uint8_t>& samChallenge,
        int sfi,
        int recordNumber,
        std::uint8_t p1);

    /**
     * Synchronizes the crypto service.
     *
     * @param dataOut The APDU dataOut field.
     */
    void synchronizeCryptoService(const std::vector<std::uint8_t>& dataOut);

    /**
     * Returns the KVC to use according to the provided write access and the
     * card's KVC.
     *
     * @return "null" if the card did not provide a KVC value and if there's no
     * default KVC value.
     */
    std::shared_ptr<std::uint8_t> computeKvc();

    /**
     * Returns the KIF to use according to the provided write access level and
     * KVC.
     *
     * @param kvc The previously computed KVC value.
     * @return "null" if the card did not provide a KIF value and if there's no
     * default KIF value.
     */
    std::shared_ptr<std::uint8_t> computeKif(const std::uint8_t* kvc);

    /**
     * Parse Rev 3
     *
     * @param apduResponseData The response data.
     */
    void parseRev3(const std::vector<std::uint8_t>& apduResponseData);

    /**
     * Parse Rev 2.4
     *
     * <p>In rev 2.4 mode, the response to the Open Secure Session command is as
     * follows:
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
     *   <li>7: not ratified (2 ratification bytes), 1-byte KCV, 4-byte
     *       challenge, no data
     *   <li>35 not ratified (2 ratification bytes), 1-byte KCV, 4-byte
     *       challenge, 29 bytes of data
     * </ul>
     *
     * @param apduResponseData The response data.
     */
    void parseRev24(const std::vector<std::uint8_t>& apduResponseData);

    /**
     * Parse Rev 1.0
     *
     * <p>In rev 1.0 mode, the response to the Open Secure Session command is as
     * follows:
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
     *   <li>35 not ratified (2 ratification bytes), 4-byte challenge, 29 bytes
     *       of data
     * </ul>
     *
     * @param apduResponseData The response data.
     */
    void parseRev10(const std::vector<std::uint8_t>& apduResponseData);

    /**
     * Parse the command response in PKI mode.
     *
     * <p>Extracts the field pkiAid, pkiSerialNumber and pkiStatus.
     *
     * @param apduResponseData The card output data.
     * @throw IllegalStateException If the response is inconsistent.
     */
    void parsePki(const std::vector<std::uint8_t>& apduResponseData);

    /** */
    void checkReceivedDataLength(int dataLength);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
