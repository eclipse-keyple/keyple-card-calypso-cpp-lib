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
#include <string>
#include <vector>

#include "keyple/card/calypso/SecureTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/SymmetricCryptoSecuritySettingAdapter.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/transaction/SecureSymmetricCryptoTransactionManager.hpp"
#include "keypop/calypso/card/transaction/SvAction.hpp"
#include "keypop/calypso/card/transaction/SvOperation.hpp"
#include "keypop/calypso/card/transaction/spi/CardTransactionCryptoExtension.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::transaction::
    SecureSymmetricCryptoTransactionManager;
using keypop::calypso::card::transaction::SvAction;
using keypop::calypso::card::transaction::SvOperation;
using keypop::calypso::card::transaction::spi::CardTransactionCryptoExtension;

/**
 * Adapter of SecureSymmetricCryptoTransactionManager.
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
template <typename T>
class SecureSymmetricCryptoTransactionManagerAdapter
: public SecureTransactionManagerAdapter<T>,
  public SecureSymmetricCryptoTransactionManager<T> {
public:
    /** */
    std::shared_ptr<DtoAdapters::TransactionContextDto> mTransactionContext;

    /** */
    bool mIsExtendedMode = false;

    /** */
    bool mIsEncryptionActive = false;

    /**
     * Builds a new instance.
     *
     * @param cardReader The card reader to be used.
     * @param card The selected card on which to operate the transaction.
     * @param symmetricCryptoSecuritySetting The symmetric crypto security
     * setting to be used.
     * @since 3.0.0
     */
    SecureSymmetricCryptoTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card,
        std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
            symmetricCryptoSecuritySetting);

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::shared_ptr<DtoAdapters::TransactionContextDto>
    getTransactionContext() const final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::shared_ptr<DtoAdapters::CommandContextDto>
    getCommandContext() const final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */

    void resetCommandContext() final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    int getPayloadCapacity() const final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    void resetTransaction() final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    void prepareNewSecureSessionIfNeeded(
        const std::shared_ptr<Command>& command) final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    bool canConfigureReadOnOpenSecureSession() const final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    T& prepareIncreaseOrDecreaseCounter(
        bool isDecreaseCommand,
        std::uint8_t sfi,
        int counterNumber,
        int incDecValue);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     * @deprecated Use processCommands(keypop::reader::ChannelControl) instead.
     */
    // T& processCommands(
    //     keypop::calypso::card::transaction::ChannelControl channelControl)
    //     final;

    /**
     * {@inheritDoc}
     *
     * <p>For each prepared command, if a pre-processing is required, then we
     * try to execute the post-processing of each of the previous commands in
     * anticipation. If at least one post-processing cannot be anticipated, then
     * we execute the block of previous commands first.
     *
     * @since 3.2.0
     */
    T& processCommands(ChannelControl channelControl) override;

    /**
     * {@inheritDoc}
     *
     * <p>Handles the post-processing of a command during a secure symmetric
     * crypto transaction. This method processes commands related to
     * counter-value adjustments (e.g., increase or decrease) that are postponed
     * and ensures proper handling of subsequent commands such as session
     * closure and stored-value operations, if applicable.
     *
     * @param commandIndex The index of the command being post-processed within
     * the list of commands.
     * @param commands The list of all commands in the transaction, including
     * the command being processed.
     * @since 3.2.1
     */
    void handleCommandPostProcessing(
        int commandIndex,
        const std::vector<std::shared_ptr<Command>>& commands) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    T& prepareVerifyPin(const std::vector<std::uint8_t>& pin) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    T& prepareChangePin(const std::vector<std::uint8_t>& newPin) final;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::shared_ptr<CardTransactionCryptoExtension> getCryptoExtension() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    T& prepareOpenSecureSession(WriteAccessLevel writeAccessLevel) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    T& prepareCloseSecureSession() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSvGet(SvOperation svOperation, SvAction svAction) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSvReload(
        int amount,
        const std::vector<std::uint8_t>& date,
        const std::vector<std::uint8_t>& time,
        const std::vector<std::uint8_t>& free) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSvReload(int amount) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSvDebit(
        int amount,
        const std::vector<std::uint8_t>& date,
        const std::vector<std::uint8_t>& time) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSvDebit(int amount) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareInvalidate() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareRehabilitate() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    T& prepareChangeKey(
        int keyIndex,
        std::uint8_t newKif,
        std::uint8_t newKvc,
        std::uint8_t issuerKif,
        std::uint8_t issuerKvc) final;

private:
    /** */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(
        typeid(SecureSymmetricCryptoTransactionManagerAdapter));

    /** */
    static const std::string MSG_PIN_NOT_AVAILABLE;

    /*
     * Commands that modify the content of the card in session have a cost on
     * the session buffer equal to the length of the outgoing data plus 6 bytes.
     */
    static const int SESSION_BUFFER_CMD_ADDITIONAL_COST;

    /** */
    static const int APDU_HEADER_LENGTH;

    /** */
    std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
        mSymmetricCryptoSecuritySetting;

    /** */
    std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
        mSymmetricCryptoCardTransactionManagerSpi;

    /** */
    std::shared_ptr<CardTransactionCryptoExtension> mCryptoExtension;

    /** */
    WriteAccessLevel mWriteAccessLevel;

    /** */
    int mPayloadCapacity = 0;

    /** */
    int mModificationsCounter = 0;

    /** */
    int mNbPostponedData = 0;

    /** */
    int mSvPostponedDataIndex = -1;

    /** */
    bool mIsSvGet = false;

    /** */
    SvOperation mSvOperation = SvOperation::RELOAD;

    /** */
    SvAction mSvAction = SvAction::DO;

    /** */
    bool mIsSvOperationInSecureSession = false;

    /**
     * Computes the session buffer size of the provided command.<br>
     * The size may be a number of bytes or 1 depending on the card
     * specificities.
     *
     * @param command The command.
     * @return A positive value.
     */
    int computeCommandSessionBufferSize(
        const std::shared_ptr<Command>& command) const;

    /**
     * Throws an exception if the multiple session is not enabled.
     *
     * @param command The command.
     * @throw SessionBufferOverflowException If the multiple session is not
     * allowed.
     */
    void
    checkMultipleSessionEnabled(const std::shared_ptr<Command>& command) const;

    /**
     * Attempts to synchronize the crypto service before executing the finalized
     * command on the card and returns "true" on successful execution.
     *
     * @param commands The commands.
     * @return "false" if the crypto service could not be synchronized before
     * transmitting the commands to the card.
     */
    bool synchronizeCryptoServiceBeforeCardProcessing(
        const std::vector<std::shared_ptr<Command>>& commands);

    /** Process any prepared crypto commands. */
    void processCryptoPreparedCommands();

    /**
     * Checks if the preconditions of an SV modifying command are satisfied and
     * updates the corresponding flags.
     *
     * @throw IllegalStateException If preconditions are not satisfied.
     */
    void checkSvModifyingCommandPreconditions(SvOperation svOperation);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
