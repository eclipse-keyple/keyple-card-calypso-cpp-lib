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

#include "keyple/card/calypso/SecureSymmetricCryptoTransactionManagerAdapter.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CommandChangeKey.hpp"
#include "keyple/card/calypso/CommandChangePin.hpp"
#include "keyple/card/calypso/CommandCloseSecureSession.hpp"
#include "keyple/card/calypso/CommandGetChallenge.hpp"
#include "keyple/card/calypso/CommandInvalidate.hpp"
#include "keyple/card/calypso/CommandManageSession.hpp"
#include "keyple/card/calypso/CommandOpenSecureSession.hpp"
#include "keyple/card/calypso/CommandRatification.hpp"
#include "keyple/card/calypso/CommandRehabilitate.hpp"
#include "keyple/card/calypso/CommandSvDebitOrUndebit.hpp"
#include "keyple/card/calypso/CommandSvGet.hpp"
#include "keyple/card/calypso/CommandSvReload.hpp"
#include "keyple/card/calypso/CommandVerifyPin.hpp"
#include "keyple/core/plugin/CardIOException.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/SessionBufferOverflowException.hpp"
#include "keypop/calypso/card/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/calypso/crypto/asymmetric/AsymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/ReaderIOException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/CardReader.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::card::calypso::CalypsoCardConstant;
using keyple::core::plugin::CardIOException;
using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::RuntimeException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::SessionBufferOverflowException;
using keypop::calypso::card::transaction::UnexpectedCommandStatusException;
using keypop::calypso::crypto::asymmetric::AsymmetricCryptoException;
using keypop::calypso::crypto::legacysam::transaction::ReaderIOException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;
using keypop::reader::CardCommunicationException;
using keypop::reader::CardReader;
using keypop::reader::ReaderCommunicationException;
using keypop::reader::selection::InvalidCardResponseException;

template <typename T>
const std::string
    SecureSymmetricCryptoTransactionManagerAdapter<T>::MSG_PIN_NOT_AVAILABLE
    = "PIN is not available for this card";
template <typename T>
const int SecureSymmetricCryptoTransactionManagerAdapter<
    T>::SESSION_BUFFER_CMD_ADDITIONAL_COST = 6;
template <typename T>
const int SecureSymmetricCryptoTransactionManagerAdapter<T>::APDU_HEADER_LENGTH
    = 5;

template <typename T>
SecureSymmetricCryptoTransactionManagerAdapter<T>::
    SecureSymmetricCryptoTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card,
        std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
            symmetricCryptoSecuritySetting)
: TransactionManagerAdapter<T>(cardReader, card)
, SecureTransactionManagerAdapter<T>(cardReader, card)
, mSymmetricCryptoSecuritySetting(symmetricCryptoSecuritySetting)
{
    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactorySpi>
        cryptoFactory = symmetricCryptoSecuritySetting
                            ->getCryptoCardTransactionManagerFactorySpi();

    /* Extended mode flag */
    mIsExtendedMode = card->isExtendedModeSupported()
                      && cryptoFactory->isExtendedModeSupported();

    if (!mIsExtendedMode) {
        SecureTransactionManagerAdapter<T>::disablePreOpenMode();
    }

    /* Adjust card & SAM payload capacities */
    mPayloadCapacity = std::min(
        static_cast<int>(card->getPayloadCapacity()),
        cryptoFactory->getMaxCardApduLengthSupported() - APDU_HEADER_LENGTH);

    /* CL-SAM-CSN.1 */
    mSymmetricCryptoCardTransactionManagerSpi
        = cryptoFactory->createCardTransactionManager(
            card->getCalypsoSerialNumberFull(),
            mIsExtendedMode,
            SecureTransactionManagerAdapter<T>::getTransactionAuditData());

    mCryptoExtension
        = std::dynamic_pointer_cast<CardTransactionCryptoExtension>(
            mSymmetricCryptoCardTransactionManagerSpi);

    mTransactionContext = std::make_shared<DtoAdapters::TransactionContextDto>(
        card, mSymmetricCryptoCardTransactionManagerSpi);

    mModificationsCounter = card->getModificationsCounter();
}

template <typename T>
std::shared_ptr<DtoAdapters::TransactionContextDto>
SecureSymmetricCryptoTransactionManagerAdapter<T>::getTransactionContext() const
{
    return mTransactionContext;
}

template <typename T>
std::shared_ptr<DtoAdapters::CommandContextDto>
SecureSymmetricCryptoTransactionManagerAdapter<T>::getCommandContext() const
{
    return std::make_shared<DtoAdapters::CommandContextDto>(
        SecureTransactionManagerAdapter<T>::mIsSecureSessionOpen,
        mIsEncryptionActive);
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<T>::resetCommandContext()
{
    SecureTransactionManagerAdapter<T>::mIsSecureSessionOpen = false;
    mIsEncryptionActive = false;
}

template <typename T>
int
SecureSymmetricCryptoTransactionManagerAdapter<T>::getPayloadCapacity() const
{
    return mPayloadCapacity;
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<T>::resetTransaction()
{
    resetCommandContext();

    mModificationsCounter
        = SecureTransactionManagerAdapter<T>::mCard->getModificationsCounter();
    mNbPostponedData = 0;
    mSvPostponedDataIndex = -1;
    mIsSvGet = false;
    mSvOperation = SvOperation::RELOAD;  // FIXME: might be a bad choice, we
                                         // might need a pointer
    mIsSvOperationInSecureSession = false;

    SecureTransactionManagerAdapter<T>::disablePreOpenMode();

    SecureTransactionManagerAdapter<T>::mCommands.clear();

    if (mTransactionContext->isSecureSessionOpen()) {
        try {
            auto cancelSecureSessionCommand
                = std::make_shared<CommandCloseSecureSession>(
                    mTransactionContext, getCommandContext(), true);
            cancelSecureSessionCommand->finalizeRequest();

            std::vector<std::shared_ptr<Command>> commands;
            commands.push_back(cancelSecureSessionCommand);
            SecureTransactionManagerAdapter<T>::executeCardCommands(
                commands, ChannelControl::KEEP_OPEN);

        } catch (const RuntimeException& e) {
            mLogger->warn(
                "Failed to abort secure session [reason=%]\n", e.getMessage());
        }

        /* Finally */
        SecureTransactionManagerAdapter<T>::mCard->restoreFiles();
        mTransactionContext->setSecureSessionOpen(false);
    }
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<
    T>::prepareNewSecureSessionIfNeeded(const std::shared_ptr<Command>& command)
{
    if (!SecureTransactionManagerAdapter<T>::mIsSecureSessionOpen) {
        return;
    }

    mModificationsCounter -= computeCommandSessionBufferSize(command);
    if (mModificationsCounter < 0) {
        checkMultipleSessionEnabled(command);
        SecureTransactionManagerAdapter<T>::mCommands.push_back(
            std::make_shared<CommandCloseSecureSession>(
                mTransactionContext,
                getCommandContext(),
                true,
                mSvPostponedDataIndex));

        SecureTransactionManagerAdapter<T>::disablePreOpenMode();

        SecureTransactionManagerAdapter<T>::mCommands.push_back(
            std::make_shared<CommandOpenSecureSession>(
                mTransactionContext,
                getCommandContext(),
                mSymmetricCryptoSecuritySetting,
                mWriteAccessLevel,
                mIsExtendedMode));

        if (mIsEncryptionActive) {
            auto session = std::make_shared<CommandManageSession>(
                mTransactionContext, getCommandContext());
            session->setEncryptionRequested(true);
            SecureTransactionManagerAdapter<T>::mCommands.push_back(session);
        }

        mModificationsCounter = SecureTransactionManagerAdapter<T>::mCard
                                    ->getModificationsCounter();
        mModificationsCounter -= computeCommandSessionBufferSize(command);
        mNbPostponedData = 0;
        mSvPostponedDataIndex = -1;
        mIsSvOperationInSecureSession = false;
    }
}

template <typename T>
int
SecureSymmetricCryptoTransactionManagerAdapter<
    T>::computeCommandSessionBufferSize(const std::shared_ptr<Command>& command)
    const
{
    return SecureTransactionManagerAdapter<T>::mCard
                   ->isModificationsCounterInBytes()
               ? command->getApduRequest()->getApdu().size()
                     + SESSION_BUFFER_CMD_ADDITIONAL_COST - APDU_HEADER_LENGTH
               : 1;
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<T>::checkMultipleSessionEnabled(
    const std::shared_ptr<Command>& command) const
{
    /*
     * CL-CSS-REQUEST.1
     * CL-CSS-SMEXCEED.1
     * CL-CSS-INFOCSS.1
     */
    if (!mSymmetricCryptoSecuritySetting->isMultipleSessionEnabled()) {
        throw SessionBufferOverflowException(
            std::string("Multiple session is not allowed. A command would ")
                + "overflow the card modifications buffer. Command: "
                + command->getName()
                + SecureTransactionManagerAdapter<
                    T>::getTransactionAuditDataAsString(),
            nullptr);
    }
}

template <typename T>
bool
SecureSymmetricCryptoTransactionManagerAdapter<
    T>::canConfigureReadOnOpenSecureSession() const
{
    return SecureTransactionManagerAdapter<T>::mIsSecureSessionOpen
           && !mSymmetricCryptoSecuritySetting->isReadOnSessionOpeningDisabled()
           && SecureTransactionManagerAdapter<T>::mCard
                      ->getPreOpenWriteAccessLevel()
                  == WriteAccessLevel::UNKOWN
           && !SecureTransactionManagerAdapter<T>::mCommands.empty()
           && SecureTransactionManagerAdapter<T>::mCommands
                      [SecureTransactionManagerAdapter<T>::mCommands.size() - 1]
                          ->getCommandRef()
                  == CardCommandRef::OPEN_SECURE_SESSION
           && !std::dynamic_pointer_cast<CommandOpenSecureSession>(
                   SecureTransactionManagerAdapter<T>::mCommands
                       [SecureTransactionManagerAdapter<T>::mCommands.size()
                        - 1])
                   ->isReadModeConfigured();
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::
    prepareIncreaseOrDecreaseCounter(
        bool isDecreaseCommand,
        std::uint8_t sfi,
        int counterNumber,
        int incDecValue)
{
    SecureTransactionManagerAdapter<T>::prepareIncreaseOrDecreaseCounter(
        isDecreaseCommand, sfi, counterNumber, incDecValue);

    return dynamic_cast<T&>(*this);
}

// template <typename T>
// T&
// SecureSymmetricCryptoTransactionManagerAdapter<T>::processCommands(
//     keypop::calypso::card::transaction::ChannelControl channelControl)
// {
//     try {
//         return processCommands(
//             keypop::reader::valueOf(static_cast<int>(channelControl)));
//
//     } catch (const CardCommunicationException& e) {
//         throw CardIOException(e.what(), Exception(e.what()));
//
//     } catch (const ReaderCommunicationException& e) {
//         throw ReaderIOException(e.what(), e);
//
//     } catch (const InvalidCardResponseException& e) {
//         throw UnexpectedCommandStatusException(e.what(), e);
//     }
// }

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::processCommands(
    ChannelControl channelControl)
{
    if (SecureTransactionManagerAdapter<T>::mCommands.empty()) {
        processCryptoPreparedCommands();
        return dynamic_cast<T&>(*this);
    }

    try {
        std::vector<std::shared_ptr<Command>> cardRequestCommands;

        for (const auto command :
             SecureTransactionManagerAdapter<T>::mCommands) {
            if (command->isCryptoServiceRequiredToFinalizeRequest()
                && (!synchronizeCryptoServiceBeforeCardProcessing(
                    cardRequestCommands))) {
                SecureTransactionManagerAdapter<T>::executeCardCommands(
                    cardRequestCommands, ChannelControl::KEEP_OPEN);
                cardRequestCommands.clear();
            }

            command->finalizeRequest();
            cardRequestCommands.push_back(command);
        }

        SecureTransactionManagerAdapter<T>::executeCardCommands(
            cardRequestCommands, channelControl);
        processCryptoPreparedCommands();

    } catch (const RuntimeException& e) {
        resetTransaction();

        /* Finally  */
        SecureTransactionManagerAdapter<T>::mCommands.clear();
        if (mIsExtendedMode
            && !SecureTransactionManagerAdapter<T>::mCard
                    ->isExtendedModeSupported()) {
            mIsExtendedMode = false;
        }

        throw;
    }

    /* Finally  */
    SecureTransactionManagerAdapter<T>::mCommands.clear();
    if (mIsExtendedMode
        && !SecureTransactionManagerAdapter<T>::mCard
                ->isExtendedModeSupported()) {
        mIsExtendedMode = false;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<T>::handleCommandPostProcessing(
    int commandIndex, const std::vector<std::shared_ptr<Command>>& commands)
{
    if (!mTransactionContext->getCard()->getIsCounterValuePostponed()) {
        return;
    }

    CardCommandRef commandRef = commands[commandIndex]->getCommandRef();

    if (commandRef != CardCommandRef::INCREASE
        && commandRef != CardCommandRef::DECREASE) {
        return;
    }

    mNbPostponedData++;
    if (commandIndex == static_cast<int>(commands.size() - 1)) {
        return;
    }

    bool isSv = false;

    for (int i = commandIndex + 1; i < static_cast<int>(commands.size()); i++) {
        commandRef = commands[i]->getCommandRef();
        if (commandRef == CardCommandRef::SV_RELOAD
            || commandRef == CardCommandRef::SV_DEBIT
            || commandRef == CardCommandRef::SV_UNDEBIT) {
            isSv = true;

        } else if (commandRef == CardCommandRef::CLOSE_SECURE_SESSION) {
            if (isSv) {
                const auto session
                    = std::dynamic_pointer_cast<CommandCloseSecureSession>(
                        commands[i]);

                if (session != nullptr) {
                    session->incrementSvPostponedDataIndex();
                }
            }
            break;
        }
    }
}

template <typename T>
bool
SecureSymmetricCryptoTransactionManagerAdapter<T>::
    synchronizeCryptoServiceBeforeCardProcessing(
        const std::vector<std::shared_ptr<Command>>& commands)
{
    for (const auto& command : commands) {
        if (!command->synchronizeCryptoServiceBeforeCardProcessing()) {
            return false;
        }
    }

    return true;
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<
    T>::processCryptoPreparedCommands()
{
    if (mSymmetricCryptoCardTransactionManagerSpi != nullptr) {
        try {
            mSymmetricCryptoCardTransactionManagerSpi->synchronize();

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }
    }
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareVerifyPin(
    const std::vector<std::uint8_t>& pin)
{
    try {
        Assert::getInstance().isEqual(
            pin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!SecureTransactionManagerAdapter<T>::mCard
                 ->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        if (mSymmetricCryptoSecuritySetting == nullptr
            || mSymmetricCryptoSecuritySetting
                   ->isPinPlainTransmissionEnabled()) {
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::unique_ptr<CommandVerifyPin>(new CommandVerifyPin(
                    getTransactionContext(), getCommandContext(), pin)));

        } else {
            /*
             * CL-PIN-PENCRYPT.1
             * CL-PIN-GETCHAL.1
             */
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::make_shared<CommandGetChallenge>(
                    getTransactionContext(), getCommandContext()));
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::make_shared<CommandVerifyPin>(
                    getTransactionContext(),
                    getCommandContext(),
                    pin,
                    *mSymmetricCryptoSecuritySetting
                         ->getPinVerificationCipheringKif(),
                    *mSymmetricCryptoSecuritySetting
                         ->getPinVerificationCipheringKvc()));
        }

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareChangePin(
    const std::vector<std::uint8_t>& newPin)
{
    try {
        Assert::getInstance().isEqual(
            newPin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!SecureTransactionManagerAdapter<T>::mCard
                 ->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        SecureTransactionManagerAdapter<T>::checkNoSecureSession();

        /* CL-PIN-MENCRYPT.1 */
        if (mSymmetricCryptoSecuritySetting == nullptr
            || mSymmetricCryptoSecuritySetting
                   ->isPinPlainTransmissionEnabled()) {
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::make_shared<CommandChangePin>(
                    getTransactionContext(), getCommandContext(), newPin));

        } else {
            /* CL-PIN-GETCHAL.1 */
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::make_shared<CommandGetChallenge>(
                    getTransactionContext(), getCommandContext()));
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::make_shared<CommandChangePin>(
                    getTransactionContext(),
                    getCommandContext(),
                    newPin,
                    *mSymmetricCryptoSecuritySetting
                         ->getPinModificationCipheringKif(),
                    *mSymmetricCryptoSecuritySetting
                         ->getPinModificationCipheringKvc()));
        }

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
std::shared_ptr<CardTransactionCryptoExtension>
SecureSymmetricCryptoTransactionManagerAdapter<T>::getCryptoExtension()
{
    return mCryptoExtension;
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareOpenSecureSession(
    WriteAccessLevel writeAccessLevel)
{
    try {
        SecureTransactionManagerAdapter<T>::checkNoSecureSession();

        if (SecureTransactionManagerAdapter<T>::mCard
                    ->getPreOpenWriteAccessLevel()
                != WriteAccessLevel::UNKOWN
            && SecureTransactionManagerAdapter<T>::mCard
                       ->getPreOpenWriteAccessLevel()
                   != writeAccessLevel) {
            mLogger->warn(
                std::string("Pre-open mode cancelled because writeAccessLevel")
                    + "mismatches writeAccessLevel used for pre-open mode "
                    + "[writeAccessLevel=%, preOpenWriteAccessLevel=%]\n",
                std::to_string(static_cast<int>(writeAccessLevel)),
                std::to_string(
                    static_cast<int>(SecureTransactionManagerAdapter<T>::mCard
                                         ->getPreOpenWriteAccessLevel())));

            SecureTransactionManagerAdapter<T>::disablePreOpenMode();
        }

        SecureTransactionManagerAdapter<T>::mCommands.push_back(
            std::make_shared<CommandOpenSecureSession>(
                mTransactionContext,
                getCommandContext(),
                mSymmetricCryptoSecuritySetting,
                writeAccessLevel,
                mIsExtendedMode));

        mWriteAccessLevel = writeAccessLevel; /* CL-KEY-INDEXPO.1 */
        SecureTransactionManagerAdapter<T>::mIsSecureSessionOpen = true;
        mIsEncryptionActive = false;
        mModificationsCounter = SecureTransactionManagerAdapter<T>::mCard
                                    ->getModificationsCounter();
        mNbPostponedData = 0;
        mSvPostponedDataIndex = -1;
        mIsSvOperationInSecureSession = false;

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareCloseSecureSession()
{
    try {
        SecureTransactionManagerAdapter<T>::checkSecureSession();

        auto reader = std::dynamic_pointer_cast<CardReader>(
            SecureTransactionManagerAdapter<T>::mCardReader);
        if (mSymmetricCryptoSecuritySetting->isRatificationMechanismEnabled()
            && reader != nullptr && reader->isContactless()) {
            /*
             * CL-RAT-CMD.1
             * CL-RAT-DELAY.1
             * CL-RAT-NXTCLOSE.1
             */
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::unique_ptr<CommandCloseSecureSession>(
                    new CommandCloseSecureSession(
                        getTransactionContext(),
                        getCommandContext(),
                        false,
                        mSvPostponedDataIndex)));
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::unique_ptr<CommandRatification>(new CommandRatification(
                    getTransactionContext(), getCommandContext())));

        } else {
            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::unique_ptr<CommandCloseSecureSession>(
                    new CommandCloseSecureSession(
                        getTransactionContext(),
                        getCommandContext(),
                        true,
                        mSvPostponedDataIndex)));
        }

    } catch (const RuntimeException& e) {
        resetTransaction();

        /* Finally */
        resetCommandContext();
        SecureTransactionManagerAdapter<T>::disablePreOpenMode();

        throw;
    }

    /* Finally */
    resetCommandContext();
    SecureTransactionManagerAdapter<T>::disablePreOpenMode();

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareSvGet(
    SvOperation svOperation, SvAction svAction)
{
    try {
        if (!SecureTransactionManagerAdapter<T>::mCard
                 ->isSvFeatureAvailable()) {
            throw UnsupportedOperationException(
                "Stored Value is not available for this card");
        }

        if (mSymmetricCryptoSecuritySetting->isSvLoadAndDebitLogEnabled()
            && !mIsExtendedMode) {
            /*
             * @see Calypso Layer ID 8.09/8.10 (200108): both reload and debit
             * logs are requested for a non rev3.2 card add two SvGet commands
             * (for RELOAD then for DEBIT).
             * CL-SV-GETNUMBER.1
             */
            SvOperation operation1 = svOperation == SvOperation::RELOAD
                                         ? SvOperation::DEBIT
                                         : SvOperation::RELOAD;

            SecureTransactionManagerAdapter<T>::mCommands.push_back(
                std::unique_ptr<CommandSvGet>(new CommandSvGet(
                    mTransactionContext,
                    getCommandContext(),
                    operation1,
                    false)));
        }

        SecureTransactionManagerAdapter<T>::mCommands.push_back(
            std::unique_ptr<CommandSvGet>(new CommandSvGet(
                mTransactionContext,
                getCommandContext(),
                svOperation,
                mIsExtendedMode)));

        mIsSvGet = true;
        mSvOperation = svOperation;
        mSvAction = svAction;

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareSvReload(
    int amount,
    const std::vector<std::uint8_t>& date,
    const std::vector<std::uint8_t>& time,
    const std::vector<std::uint8_t>& free)
{
    try {
        /*
         * FIXME: Assert::isInRange() only takes size_t bounds, so comparing
         * against the negative CalypsoCardConstant::SV_LOAD_MIN_VALUE wraps
         * it around to a huge unsigned value and makes every amount
         * (including valid ones) fail the lower-bound check. Checked
         * manually here instead of going through Assert until isInRange()
         * gains a signed overload.
         */
        if (amount < CalypsoCardConstant::SV_LOAD_MIN_VALUE
            || amount > CalypsoCardConstant::SV_LOAD_MAX_VALUE) {
            throw IllegalArgumentException(
                "Argument [amount] has a value [" + std::to_string(amount)
                + "] out of range ["
                + std::to_string(CalypsoCardConstant::SV_LOAD_MIN_VALUE) + ".."
                + std::to_string(CalypsoCardConstant::SV_LOAD_MAX_VALUE)
                + "].");
        }

        Assert::getInstance()
            .isEqual(date.size(), 2, "date")
            .isEqual(time.size(), 2, "time")
            .isEqual(free.size(), 2, "free");

        checkSvModifyingCommandPreconditions(SvOperation::RELOAD);

        auto command = std::make_shared<CommandSvReload>(
            mTransactionContext,
            getCommandContext(),
            amount,
            date,
            time,
            free,
            mIsExtendedMode);

        prepareNewSecureSessionIfNeeded(command);
        SecureTransactionManagerAdapter<T>::mCommands.push_back(command);

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
void
SecureSymmetricCryptoTransactionManagerAdapter<
    T>::checkSvModifyingCommandPreconditions(SvOperation svOperation)
{
    /*
     * CL-SV-GETDEBIT.1
     * CL-SV-GETRLOAD.1
     */
    if (!mIsSvGet) {
        throw IllegalStateException(
            "SV modifying command must follow an SV Get command");
    }

    mIsSvGet = false;
    if (svOperation != mSvOperation) {
        throw IllegalStateException(
            std::string("SV operation is inconsistent with previous SV Get")
            + " command. Expected: "
            + std::to_string(static_cast<int>(mSvOperation))
            + ", Actual: " + std::to_string(static_cast<int>(svOperation)));
    }

    /* CL-SV-1PCSS.1 */
    if (SecureTransactionManagerAdapter<T>::mIsSecureSessionOpen) {
        if (mIsSvOperationInSecureSession) {
            throw IllegalStateException(
                "Only one SV modifying command is allowed per Secure Session");
        }

        mIsSvOperationInSecureSession = true;
        mSvPostponedDataIndex = mNbPostponedData;
        mNbPostponedData++;
    }
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareSvReload(int amount)
{
    const std::vector<std::uint8_t> zero = {0x00, 0x00};
    prepareSvReload(amount, zero, zero, zero);

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareSvDebit(
    int amount,
    const std::vector<std::uint8_t>& date,
    const std::vector<std::uint8_t>& time)
{
    try {
        /* @see Calypso Layer ID 8.02 (200108) */

        /* CL-SV-DEBITVAL.1 */
        Assert::getInstance()
            .isInRange(
                amount,
                CalypsoCardConstant::SV_DEBIT_MIN_VALUE,
                CalypsoCardConstant::SV_DEBIT_MAX_VALUE,
                "amount")
            .isEqual(date.size(), 2, "date")
            .isEqual(time.size(), 2, "time");

        checkSvModifyingCommandPreconditions(SvOperation::DEBIT);

        auto command = std::make_shared<CommandSvDebitOrUndebit>(
            mSvAction == SvAction::DO,
            mTransactionContext,
            getCommandContext(),
            amount,
            date,
            time,
            mIsExtendedMode,
            mSymmetricCryptoSecuritySetting->isSvNegativeBalanceAuthorized());

        prepareNewSecureSessionIfNeeded(command);
        SecureTransactionManagerAdapter<T>::mCommands.push_back(command);

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareSvDebit(int amount)
{
    const std::vector<std::uint8_t> zero = {0x00, 0x00};

    prepareSvDebit(amount, zero, zero);

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareInvalidate()
{
    try {
        if (SecureTransactionManagerAdapter<T>::mCard->isDfInvalidated()) {
            throw IllegalStateException("Card is already invalidated");
        }

        auto command = std::make_shared<CommandInvalidate>(
            mTransactionContext, getCommandContext());

        prepareNewSecureSessionIfNeeded(command);
        SecureTransactionManagerAdapter<T>::mCommands.push_back(command);

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareRehabilitate()
{
    try {
        if (!SecureTransactionManagerAdapter<T>::mCard->isDfInvalidated()) {
            throw IllegalStateException("Card is not invalidated");
        }

        auto command = std::make_shared<CommandRehabilitate>(
            mTransactionContext, getCommandContext());

        prepareNewSecureSessionIfNeeded(command);
        SecureTransactionManagerAdapter<T>::mCommands.push_back(command);

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
SecureSymmetricCryptoTransactionManagerAdapter<T>::prepareChangeKey(
    int keyIndex,
    std::uint8_t newKif,
    std::uint8_t newKvc,
    std::uint8_t issuerKif,
    std::uint8_t issuerKvc)
{
    try {
        if (SecureTransactionManagerAdapter<T>::mCard->getProductType()
            == CalypsoCard::ProductType::BASIC) {
            throw UnsupportedOperationException(
                "'Change Key' command is not available for this card");
        }

        SecureTransactionManagerAdapter<T>::checkNoSecureSession();
        Assert::getInstance().isInRange(keyIndex, 1, 3, "keyIndex");

        /* CL-KEY-CHANGE.1 */
        SecureTransactionManagerAdapter<T>::mCommands.push_back(
            std::unique_ptr<CommandGetChallenge>(new CommandGetChallenge(
                mTransactionContext, getCommandContext())));
        SecureTransactionManagerAdapter<T>::mCommands.push_back(
            std::unique_ptr<CommandChangeKey>(new CommandChangeKey(
                mTransactionContext,
                getCommandContext(),
                keyIndex,
                newKif,
                newKvc,
                issuerKif,
                issuerKvc)));

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

/* Explicit template instantiations for concrete transaction manager bases */
#include "keypop/calypso/card/cpp/SecureExtendedModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/cpp/SecureRegularModeTransactionManagerBase.hpp"

template class keyple::card::calypso::
    SecureSymmetricCryptoTransactionManagerAdapter<
        keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase>;

template class keyple::card::calypso::
    SecureSymmetricCryptoTransactionManagerAdapter<
        keypop::calypso::card::cpp::SecureRegularModeTransactionManagerBase>;
