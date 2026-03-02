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

#include "keyple/card/calypso/SecurePkiModeTransactionManagerAdapter.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CommandChangePin.hpp"
#include "keyple/card/calypso/CommandCloseSecureSession.hpp"
#include "keyple/card/calypso/CommandGetDataCertificate.hpp"
#include "keyple/card/calypso/CommandOpenSecureSession.hpp"
#include "keyple/card/calypso/CommandVerifyPin.hpp"
#include "keyple/core/plugin/CardIOException.hpp"
#include "keyple/core/plugin/ReaderIOException.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/transaction/InvalidCertificateException.hpp"
#include "keypop/calypso/card/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/calypso/crypto/asymmetric/AsymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/CertificateValidationException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::plugin::CardIOException;
using keyple::core::plugin::ReaderIOException;
using keyple::core::util::Assert;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::RuntimeException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::transaction::InvalidCertificateException;
using keypop::calypso::card::transaction::UnexpectedCommandStatusException;
using keypop::calypso::crypto::asymmetric::AsymmetricCryptoException;
using keypop::calypso::crypto::asymmetric::certificate::
    CertificateValidationException;
using keypop::reader::CardCommunicationException;
using keypop::reader::ReaderCommunicationException;
using keypop::reader::selection::InvalidCardResponseException;

const std::string SecurePkiModeTransactionManagerAdapter::MSG_PIN_NOT_AVAILABLE
    = "PIN is not available for this card";
const std::string
    SecurePkiModeTransactionManagerAdapter ::MSG_INVALID_CARD_CERTIFICATE
    = "Invalid card certificate";
const std::string
    SecurePkiModeTransactionManagerAdapter ::MSG_INVALID_CA_CERTIFICATE
    = "Invalid CA certificate";

SecurePkiModeTransactionManagerAdapter::SecurePkiModeTransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> cardReader,
    std::shared_ptr<CalypsoCardAdapter> card,
    std::shared_ptr<AsymmetricCryptoSecuritySettingAdapter>
        asymmetricCryptoSecuritySetting)
: TransactionManagerAdapter<SecurePkiModeTransactionManager>(cardReader, card)
, SecureTransactionManagerAdapter<SecurePkiModeTransactionManager>(
      cardReader, card)
, mAsymmetricCryptoSecuritySetting(asymmetricCryptoSecuritySetting)
, mPayloadCapacity(card->getPayloadCapacity())
{
    std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
        asymmetricCryptoCardTransactionManagerSpi
        = asymmetricCryptoSecuritySetting
              ->getCryptoCardTransactionManagerFactorySpi()
              ->createCardTransactionManager();

    mCryptoExtension
        = std::dynamic_pointer_cast<CardTransactionCryptoExtension>(
            asymmetricCryptoCardTransactionManagerSpi);

    mTransactionContext = std::make_shared<DtoAdapters::TransactionContextDto>(
        card, asymmetricCryptoCardTransactionManagerSpi);

    // C++ secure random setup
    std::random_device rd;
    std::mt19937 gen(rd());
}

void
SecurePkiModeTransactionManagerAdapter::resetCommandContext()
{
    mIsSecureSessionOpen = false;
}

std::shared_ptr<DtoAdapters::TransactionContextDto>
SecurePkiModeTransactionManagerAdapter::getTransactionContext() const
{
    return mTransactionContext;
}

std::shared_ptr<DtoAdapters::CommandContextDto>
SecurePkiModeTransactionManagerAdapter::getCommandContext() const
{
    return std::make_shared<DtoAdapters::CommandContextDto>(
        mIsSecureSessionOpen, false);
}

int
SecurePkiModeTransactionManagerAdapter::getPayloadCapacity() const
{
    return mPayloadCapacity;
}

void
SecurePkiModeTransactionManagerAdapter::resetTransaction()
{
    resetCommandContext();

    mIsGetDataCardCertificatePrepared = false;
    mIsGetDataCaCertificatePrepared = false;

    disablePreOpenMode();

    mCommands.clear();

    if (mTransactionContext->isSecureSessionOpen()) {
        try {
            auto cancelSecureSessionCommand
                = std::make_shared<CommandCloseSecureSession>(
                    mTransactionContext, getCommandContext(), true);

            cancelSecureSessionCommand->finalizeRequest();
            std::vector<std::shared_ptr<Command>> commands(1);
            commands.push_back(cancelSecureSessionCommand);
            executeCardCommands(commands, ChannelControl::KEEP_OPEN);

        } catch (const RuntimeException& e) {
            mLogger->warn(
                "Failed to abort secure session [reason=%]\n", e.what());
        }

        /* Finally */
        mCard->restoreFiles();
        mTransactionContext->setSecureSessionOpen(false);
    }
}

void
SecurePkiModeTransactionManagerAdapter::prepareNewSecureSessionIfNeeded(
    const std::shared_ptr<Command>& /*command*/)
{
    /* NOP */
}

bool
SecurePkiModeTransactionManagerAdapter::canConfigureReadOnOpenSecureSession()
    const
{
    return mIsSecureSessionOpen && !mCommands.empty()
           && mCommands[mCommands.size() - 1]->getCommandRef()
                  == CardCommandRef::OPEN_SECURE_SESSION
           && !std::dynamic_pointer_cast<CommandOpenSecureSession>(
                   mCommands[mCommands.size() - 1])
                   ->isReadModeConfigured();
}

SecurePkiModeTransactionManager&
SecurePkiModeTransactionManagerAdapter::prepareVerifyPin(
    const std::vector<std::uint8_t>& pin)
{
    try {
        Assert::getInstance().isEqual(
            pin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");
        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        mCommands.push_back(
            std::make_shared<CommandVerifyPin>(
                mTransactionContext, getCommandContext(), pin));

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return *this;
}

SecurePkiModeTransactionManager&
SecurePkiModeTransactionManagerAdapter::prepareChangePin(
    const std::vector<std::uint8_t>& newPin)
{
    try {
        Assert::getInstance().isEqual(
            newPin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");
        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        /* CL-PIN-MENCRYPT.1 */
        mCommands.push_back(
            std::make_shared<CommandChangePin>(
                mTransactionContext, getCommandContext(), newPin));

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return *this;
}

SecurePkiModeTransactionManager&
SecurePkiModeTransactionManagerAdapter::prepareGetData(GetDataTag tag)
{
    SecureTransactionManagerAdapter<
        SecurePkiModeTransactionManager>::prepareGetData(tag);

    if (tag == GetDataTag::CARD_CERTIFICATE) {
        mIsGetDataCardCertificatePrepared = true;

    } else if (tag == GetDataTag::CA_CERTIFICATE) {
        mIsGetDataCaCertificatePrepared = true;
    }

    return *this;
}

// SecurePkiModeTransactionManager&
// SecurePkiModeTransactionManagerAdapter::processCommands(
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
//         throw ReaderIOException(e.what(), Exception(e.what()));
//
//     } catch (const InvalidCardResponseException& e) {
//         throw UnexpectedCommandStatusException(e.what(), e);
//     }
// }

SecurePkiModeTransactionManager&
SecurePkiModeTransactionManagerAdapter::processCommands(
    ChannelControl channelControl)
{
    if (mCommands.empty()) {
        return *this;
    }

    try {
        /*
         * In the case that the CA certificate is missing before the parsing of
         * the response to the "open secure session" command, we seamlessly
         * trigger the execution of Get Data commands to fetch it. Depending on
         * the current status of the session, these commands might also be
         * integrated to the session hash. We need to keep the channel open and
         * close or keep it open as expected after the execution of the Get Data
         * commands (role of mOriginalChannelControl).
         */
        mOriginalChannelControl = channelControl;
        if (mCard->getCaCertificate().size() == 0
            && !mIsGetDataCaCertificatePrepared) {
            executeCardCommands(mCommands, ChannelControl::KEEP_OPEN);
        } else {
            executeCardCommands(mCommands, channelControl);
        }

    } catch (const RuntimeException& e) {
        resetTransaction();

        /* Finally */
        mCommands.clear();

        throw;
    }

    /* Finally */
    mCommands.clear();

    return *this;
}

void
SecurePkiModeTransactionManagerAdapter::parseCommandResponse(
    const std::shared_ptr<Command>& command,
    const std::shared_ptr<ApduResponseApi>& apduResponse)
{
    if (command->getCommandRef() == CardCommandRef::OPEN_SECURE_SESSION) {
        checkCardCertificateAndGetCardPublicKey();
    }

    command->parseResponse(apduResponse);
}

void
SecurePkiModeTransactionManagerAdapter ::
    checkCardCertificateAndGetCardPublicKey()
{
    /* Parse the card certificate raw data */
    std::shared_ptr<CardCertificateSpi> cardCertificateSpi
        = parseCardCertificate();

    if (!Arrays::equals(
            mCard->getApplicationSerialNumber(),
            cardCertificateSpi->getCardSerialNumber())) {
        throw InvalidCertificateException(
            "Card serial number and certificate card serial number mismatch");
    }

    /* Try to retrieve the issuer certificate content from the store */
    std::shared_ptr<CaCertificateContentSpi> caCertificateContentSpi
        = mAsymmetricCryptoSecuritySetting->getCaCertificate(
            cardCertificateSpi->getIssuerPublicKeyReference());

    /*
     * If the issuer certificate content is not already registered, then
     * retrieve it from the card.
     */
    if (caCertificateContentSpi == nullptr) {
        /*
         * Read the CA certificate from the card using the original channel
         * control.
         */
        readCaCertificate();

        /* Parse the CA certificate raw data */
        std::shared_ptr<CaCertificateSpi> caCertificateSpi
            = parseCaCertificate();

        /* Register the CA certificate into the store */
        mAsymmetricCryptoSecuritySetting->addCaCertificate(
            std::dynamic_pointer_cast<CaCertificate>(caCertificateSpi));

        /* Retrieve the CA certificate content from the store */
        caCertificateContentSpi
            = mAsymmetricCryptoSecuritySetting->getCaCertificate(
                cardCertificateSpi->getIssuerPublicKeyReference());

    } else {
        /* Force the closing of the channel if originally requested */
        if (mOriginalChannelControl == ChannelControl::CLOSE_AFTER) {
            executeCardCommands({}, ChannelControl::CLOSE_AFTER);
        }
    }

    /*
     * Check the card certificate using the issuer certificate content and
     * extract the public key.
     */
    std::shared_ptr<CardPublicKeySpi> cardPublicKeySpi;

    try {
        cardPublicKeySpi = cardCertificateSpi->checkCertificateAndGetPublicKey(
            caCertificateContentSpi);

    } catch (const CertificateValidationException& e) {
        throw InvalidCertificateException(MSG_INVALID_CARD_CERTIFICATE, e);

    } catch (const AsymmetricCryptoException& e) {
        throw CryptoException("Failed to check the card certificate", e);
    }

    /* Save the card public key into the card image */
    mCard->setCardPublicKeySpi(cardPublicKeySpi);
}

std::shared_ptr<CardCertificateSpi>
SecurePkiModeTransactionManagerAdapter::parseCardCertificate()
{
    const std::vector<std::uint8_t> cardCertificateBytes
        = mCard->getCardCertificate();

    std::shared_ptr<CardCertificateParserSpi> cardCertificateParser
        = mAsymmetricCryptoSecuritySetting->getCardCertificateParser(
            cardCertificateBytes[0]);

    if (cardCertificateParser == nullptr) {
        throw IllegalStateException(
            "No certificate parser registered for type "
            + HexUtil::toHex(cardCertificateBytes[0]));
    }

    try {
        return cardCertificateParser->parseCertificate(cardCertificateBytes);

    } catch (const CertificateValidationException& e) {
        throw InvalidCertificateException(MSG_INVALID_CARD_CERTIFICATE, e);
    }
}

std::shared_ptr<CaCertificateSpi>
SecurePkiModeTransactionManagerAdapter::parseCaCertificate()
{
    const std::vector<std::uint8_t> caCertificateBytes
        = mCard->getCaCertificate();

    std::shared_ptr<CaCertificateParserSpi> caCertificateParser
        = mAsymmetricCryptoSecuritySetting->getCaCertificateParser(
            caCertificateBytes[0]);

    if (caCertificateParser == nullptr) {
        throw IllegalStateException(
            "No certificate parser registered for type "
            + HexUtil::toHex(caCertificateBytes[0]));
    }

    try {
        return caCertificateParser->parseCertificate(caCertificateBytes);

    } catch (const CertificateValidationException& e) {
        throw InvalidCertificateException(MSG_INVALID_CA_CERTIFICATE, e);
    }
}

void
SecurePkiModeTransactionManagerAdapter::readCaCertificate()
{
    std::vector<std::shared_ptr<Command>> commands(2);

    commands.push_back(
        std::make_shared<CommandGetDataCertificate>(
            mTransactionContext, getCommandContext(), false, true));
    commands.push_back(
        std::make_shared<CommandGetDataCertificate>(
            mTransactionContext, getCommandContext(), false, false));

    executeCardCommands(commands, mOriginalChannelControl);
}

std::shared_ptr<CardTransactionCryptoExtension>
SecurePkiModeTransactionManagerAdapter::getCryptoExtension()
{
    return mCryptoExtension;
}

SecurePkiModeTransactionManager&
SecurePkiModeTransactionManagerAdapter::prepareOpenSecureSession()
{
    checkNoSecureSession();

    if (mCard->getCardCertificate().size() == 0
        && !mIsGetDataCardCertificatePrepared) {
        prepareGetData(GetDataTag::CARD_CERTIFICATE);
    }

    std::vector<std::uint8_t> terminalChallenge(8);
    mSecureRandom->nextBytes(terminalChallenge);

    mCommands.push_back(
        std::make_shared<CommandOpenSecureSession>(
            mTransactionContext, getCommandContext(), terminalChallenge));

    mIsSecureSessionOpen = true;

    return *this;
}

SecurePkiModeTransactionManager&
SecurePkiModeTransactionManagerAdapter::prepareCloseSecureSession()
{
    try {
        checkSecureSession();
        mCommands.push_back(
            std::make_shared<CommandCloseSecureSession>(
                mTransactionContext, getCommandContext(), false));

    } catch (const std::exception& e) {
        resetTransaction();

        /* Finally */
        resetCommandContext();
        disablePreOpenMode();

        throw;
    }

    /* Finally */
    resetCommandContext();
    disablePreOpenMode();

    return *this;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
