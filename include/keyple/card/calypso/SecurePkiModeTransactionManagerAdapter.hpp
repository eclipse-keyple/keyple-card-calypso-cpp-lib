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

#include <memory>
#include <random>
#include <string>
#include <vector>

#include "keyple/card/calypso/AsymmetricCryptoSecuritySettingAdapter.hpp"
#include "keyple/card/calypso/SecureTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/cpp/SecureRandom.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/transaction/SecurePkiModeTransactionManager.hpp"
#include "keypop/calypso/card/transaction/spi/CardTransactionCryptoExtension.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CardCertificateSpi.hpp"
#include "keypop/reader/ChannelControl.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::card::calypso::cpp::SecureRandom;
using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::transaction::SecurePkiModeTransactionManager;
using keypop::calypso::card::transaction::spi::CardTransactionCryptoExtension;
using keypop::calypso::crypto::asymmetric::certificate::spi::CaCertificateSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::CardCertificateSpi;
using keypop::reader::ChannelControl;

/**
 * Adapter of SecurePkiModeTransactionManager.
 *
 * @since 3.1.0
 */
class SecurePkiModeTransactionManagerAdapter final
: public SecureTransactionManagerAdapter<SecurePkiModeTransactionManager>,
  public SecurePkiModeTransactionManager {
public:
    /**
     * Builds a new instance.
     *
     * @param cardReader The card reader to be used.
     * @param card The selected card on which to operate the transaction.
     * @param asymmetricCryptoSecuritySetting The asymmetric crypto security
     * setting to be used.
     * @since 3.1.0
     */
    SecurePkiModeTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card,
        std::shared_ptr<AsymmetricCryptoSecuritySettingAdapter>
            asymmetricCryptoSecuritySetting);

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    void resetCommandContext() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    std::shared_ptr<DtoAdapters::TransactionContextDto>
    getTransactionContext() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    std::shared_ptr<DtoAdapters::CommandContextDto>
    getCommandContext() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    int getPayloadCapacity() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    void resetTransaction() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    void prepareNewSecureSessionIfNeeded(
        const std::shared_ptr<Command>& command) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    bool canConfigureReadOnOpenSecureSession() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    SecurePkiModeTransactionManager&
    prepareVerifyPin(const std::vector<std::uint8_t>& pin) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    SecurePkiModeTransactionManager&
    prepareChangePin(const std::vector<std::uint8_t>& newPin) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    SecurePkiModeTransactionManager& prepareGetData(GetDataTag tag) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     * @deprecated Use processCommands(keypop::reader::ChannelControl) instead.
     */
    // SecurePkiModeTransactionManager& processCommands(
    //     keypop::calypso::card::transaction::ChannelControl channelControl)
    //     override;

    /**
     * {@inheritDoc}
     *
     * @since 3.2.0
     */
    SecurePkiModeTransactionManager&
    processCommands(ChannelControl channelControl) override;

    /**
     * Parses the command's response and performs the necessary actions based on
     * the command type.
     *
     * @param command The command.
     * @param apduResponse The response from the card.
     * @throw CardCommandException If there is an error in the card command.
     * @since 3.1.0
     */
    void parseCommandResponse(
        const std::shared_ptr<Command>& command,
        const std::shared_ptr<ApduResponseApi>& apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    std::shared_ptr<CardTransactionCryptoExtension>
    getCryptoExtension() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    SecurePkiModeTransactionManager& prepareOpenSecureSession() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    SecurePkiModeTransactionManager& prepareCloseSecureSession() override;

private:
    /** */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(
        typeid(SecurePkiModeTransactionManagerAdapter));

    /** */
    static const std::string MSG_PIN_NOT_AVAILABLE;
    static const std::string MSG_INVALID_CARD_CERTIFICATE;
    static const std::string MSG_INVALID_CA_CERTIFICATE;

    /** */
    std::shared_ptr<DtoAdapters::TransactionContextDto> mTransactionContext;

    /** */
    std::shared_ptr<AsymmetricCryptoSecuritySettingAdapter>
        mAsymmetricCryptoSecuritySetting;

    /** */
    std::shared_ptr<CardTransactionCryptoExtension> mCryptoExtension;

    /** */
    std::unique_ptr<SecureRandom> mSecureRandom;

    /** */
    int mPayloadCapacity;

    /** */
    ChannelControl mOriginalChannelControl;

    /** */
    bool mIsGetDataCardCertificatePrepared;

    /** */
    bool mIsGetDataCaCertificatePrepared;

    /**
     * Extracts the card public key using the PKI chain of trust and place it
     * into the card image.
     */
    void checkCardCertificateAndGetCardPublicKey();

    /**
     * Parses the card certificate placed into the card image.
     *
     * @return A non-null reference.
     * @throw IllegalStateException If the certificate parser is not registered.
     * @throw InvalidCertificateException If the certificate is invalid.
     */
    std::shared_ptr<CardCertificateSpi> parseCardCertificate();

    /**
     * Parses the CA certificate placed into the card image.
     *
     * @return A non-null reference.
     * @throw IllegalStateException If the certificate parser is not registered.
     */
    std::shared_ptr<CaCertificateSpi> parseCaCertificate();

    /**
     * Executes Get Data commands to retrieve the CA certificate from the card.
     * The result will available in the card image.
     */
    void readCaCertificate();
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
