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

#include "CommonSamTransactionManagerAdapter.h"

/* Keyple Card Calypso */
#include "CalypsoSamCommandException.h"
#include "CardBrokenCommunicationException.h"
#include "ReaderBrokenCommunicationException.h"
#include "UnexpectedStatusWordException.h"

/* Keyple Core Util */
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

CommonSamTransactionManagerAdapter::CommonSamTransactionManagerAdapter(
  const std::shared_ptr<ProxyReaderApi> samReader, 
  const std::shared_ptr<CalypsoSamAdapter> sam, 
  const std::shared_ptr<SamSecuritySettingAdapter> securitySetting)
: SamTransactionManager(sam, securitySetting, nullptr);
  mSamReader(samReader),
  mSam(sam),
  mSecuritySetting(securitySetting),
  mDefaultKeyDiversifier(sam->getSerialNumber()) {}

CommonSamTransactionManagerAdapter::CommonSamTransactionManagerAdapter(
  const std::shared_ptr<SmartCard> targetSmartCard,
  const std::shared_ptr<CommonSecuritySettingAdapter> securitySetting,
  const std::vector<uint8_t>& defaultKeyDiversifier,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
: SamTransactionManager(targetSmartCard, securitySetting, transactionAuditData),
  mSamReader(securitySetting->getControlSamReader()),
  mSam(securitySetting->getControlSam()),
  mSecuritySetting(securitySetting),
  mDefaultKeyDiversifier(defaultKeyDiversifier) {}

const std::shared_ptr<CardReader> CommonSamTransactionManagerAdapter::getSamReader() const
{
    return mSamReader;
}

const std::shared_ptr<CalypsoSam> CommonSamTransactionManagerAdapter::getCalypsoSam() const
{
    return mSam;
}

SamTransactionManager& CommonSamTransactionManagerAdapter::prepareComputeSignature(
    const std::shared_ptr<SignatureComputationData> data)
{

    auto dataAdapter = std::dynamic_pointer_cast<SignatureComputationDataAdapter> data;

    if (!dataAdapter) {
        throw IllegalArgumentException("The provided data must be an instance of " \
                                       "'SignatureComputationDataAdapter'");
    }

    Assert::getInstance().notNull(dataAdapter, "input/output data")
                         .notNull(dataAdapter->getData(), "data to sign");

    Assert::getInstance().isInRange(dataAdapter->getData().size(),
                                    1,
                                    dataAdapter->isSamTraceabilityMode() ? 206 : 208,
                                    "length of data to sign")
                         .isInRange(dataAdapter->getSignatureSize(), 1, 8, "signature size")
                         .isTrue(!dataAdapter->isSamTraceabilityMode() || 
                                 (dataAdapter->getTraceabilityOffset() >= 0 && 
                                  dataAdapter->getTraceabilityOffset() <= 
                                  ((dataAdapter->getData().size() * 8) - 
                                   (dataAdapter->isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
                                 "traceability offset is in range [0.." + 
                                 std::to_string(((dataAdapter->getData().size() * 8) -
                                                 (dataAdapter->isPartialSamSerialNumber() ? 
                                                     7 * 8 : 8 * 8)) + 
                                 "]")
                         .isTrue(dataAdapter->getKeyDiversifier() == nullptr || 
                                 (dataAdapter->getKeyDiversifier().size() >= 1 && 
                                  dataAdapter->getKeyDiversifier().size() <= 8),
                                 "key diversifier size is in range [1..8]");

    prepareSelectDiversifierIfNeeded(dataAdapter->getKeyDiversifier());
    mSamCommands.push_back(std::make_shared<CmdSamPsoComputeSignature>(mSam->getProductType(), 
                                                                       dataAdapter));

    return *this;
}

SamTransactionManager& CommonSamTransactionManagerAdapter::prepareVerifySignature(
    const std::shared_ptr<SignatureVerificationData> data)
{
    auto dataAdapter = std::dynamic_pointer_cast<SignatureVerificationDataAdapter> data;

    if (!dataAdapter) {
        throw IllegalArgumentException("The provided data must be an instance of " \
                                       "'SignatureVerificationDataAdapter'");
    }

    Assert::getInstance().notNull(dataAdapter, "input/output data")
                         .notNull(dataAdapter->getData(), "signed data to verify")
                         .notNull(dataAdapter->getSignature(), "signature")
    
    Assert::getInstance().isInRange(dataAdapter->getData().length,
                                    1,
                                    dataAdapter->isSamTraceabilityMode() ? 206 : 208,
                                    "length of signed data to verify")
                         .isInRange(dataAdapter->getSignature().length, 1, 8, "signature size")
                         .isTrue(!dataAdapter->isSamTraceabilityMode() || 
                                 (dataAdapter->getTraceabilityOffset() >= 0 && 
                                  dataAdapter->getTraceabilityOffset() <= 
                                      ((dataAdapter->getData().length * 8) - 
                                       (dataAdapter->isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))),
                                 "traceability offset is in range [0.."+ 
                                 std::to_string(((dataAdapter->getData().size() * 8)) - 
                                                (dataAdapter->isPartialSamSerialNumber() ? 
                                                    7 * 8 : 8 * 8)) + 
                                 "]")
                         .isTrue(dataAdapter->getKeyDiversifier() == nullptr || 
                                 (dataAdapter->getKeyDiversifier().length >= 1 && 
                                  dataAdapter->getKeyDiversifier().length <= 8),
                                 "key diversifier size is in range [1..8]");

    /* Check SAM revocation status if requested */
    if (dataAdapter->isSamRevocationStatusVerificationRequested()) {
        Assert::getInstance().notNull(securitySetting, "security settings")
                             .notNull(securitySetting->getSamRevocationServiceSpi(), 
                                      "SAM revocation service");

        /* Extract the SAM serial number and the counter value from the data */
        const std::vector<uint8_t> samSerialNumber =
            ByteArrayUtil::extractBytes(dataAdapter->getData(),
                                        dataAdapter->getTraceabilityOffset(),
                                        dataAdapter->isPartialSamSerialNumber() ? 3 : 4);

        const int samCounterValue = 
            ByteArrayUtil::extractInt(
                ByteArrayUtil::extractBytes(dataAdapter->getData(),
                                            dataAdapter->getTraceabilityOffset() + 
                                            dataAdapter->isPartialSamSerialNumber() ? 3 * 8 : 4 * 8,
                                            3),
                0,
                3,
                false);

        /* Is SAM revoked ? */
        if (mSecuritySetting->getSamRevocationServiceSpi()->isSamRevoked(samSerialNumber, 
                                                                         samCounterValue)) {
            throw SamRevokedException(
                      StringUtils::format("SAM with serial number '%s' and counter value '%d' is " \
                                          "revoked.",
                                          HexUtil::toHex(samSerialNumber), 
                                          samCounterValue));
        }
    }

    prepareSelectDiversifierIfNeeded(dataAdapter->getKeyDiversifier());
    samCommands.push_back(std::make_shared<CmdSamPsoVerifySignature>(mSam->getProductType(),
                                                                     dataAdapter));
    
    return *this;
}

SamTransactionManager& CommonSamTransactionManagerAdapter::processCommands()
{
    if (mSamCommands.empty()) {
        return *this;
    }

    try {
        /* Get the list of C-APDU to transmit */
        const std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests = 
            getApduRequests(samCommands);

        /* Wrap the list of C-APDUs into a card request */
        auto cardRequest = std::make_shared<CardRequestAdapter>(apduRequests, true);

        /* Transmit the commands to the SAM */
        const std::shared_ptr<CardResponseApi> cardResponse = transmitCardRequest(cardRequest);

        /* Retrieve the list of R-APDUs */
        const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses = 
            cardResponse->getApduResponses();

        /*
         * If there are more responses than requests, then we are unable to fill the card image. In
         * this case we stop processing immediately because it may be a case of fraud, and we throw
         * an exception.
         */
        if (apduResponses.size() > apduRequests.size()) {
            throw InconsistentDataException("The number of SAM commands/responses does not match:" \
                                            " nb commands = " +
                                            std::to_string(apduRequests.size()) +
                                            ", nb responses = " + 
                                            std::to_string(apduResponses.size()));
        }

        /*
         * We go through all the responses (and not the requests) because there may be fewer in the
         * case of an error that occurred in strict mode. In this case the last response will raise
         * an exception.
         */
        for (int i = 0; i < static_cast<int>(apduResponses.size()); i++) {
            try {
                mSamCommands[i]->setApduResponse(apduResponses[i]->checkStatus();
            
            } catch (const CalypsoSamCommandException& e) {
                if (mSamCommands[i]->getCommandRef() == CalypsoSamCommand::PSO_VERIFY_SIGNATURE) {
                    try {
                        /* C++: equivalent of "instance of" of reference type... */  
                        dynamic_cast<CalypsoSamSecurityDataException &>(e);
                    
                        throw InvalidSignatureException(
                              "Invalid signature.", 
                              std::make_shared<CalypsoSamSecurityDataException>(e));
                    } catch (const std::bad_cast& e) {
                        /* C++: do nothing */
                        (void)e;
                    }
                }

                throw UnexpectedCommandStatusException(MSG_SAM_COMMAND_ERROR + 
                                                       "while processing responses to SAM " \
                                                       "commands: " +
                                                       e.getCommand() +
                                                       getTransactionAuditDataAsString(),
                                                       e);
            }
        }

        /*
         * Finally, if no error has occurred and there are fewer responses than requests, then we
         * throw an exception.
         */
        if (apduResponses.size() < apduRequests.size()) {
            throw InconsistentDataException("The number of SAM commands/responses does not match:" \
                                            " nb commands = " +
                                            std::to_string(apduRequests.size()) +
                                            ", nb responses = " +
                                            std::to_string(apduResponses.size()));
        }
    }

    /* Reset the list of commands (finally) */
    mSamCommands.clear();
    
    return *this;
}

std::shared_ptr<CardResponseApi> CommonSamTransactionManagerAdapter::transmitCardRequest(
    const std::shared_ptr<CardRequestSpi> cardRequest) 
{
    std::shared_ptr<CardResponseApi> cardResponse = nullptr;

    try {
        cardResponse = mSamReader->transmitCardRequest(cardRequest, ChannelControl::KEEP_OPEN);
    
    } catch (const ReaderBrokenCommunicationException& e) {
        saveTransactionAuditData(cardRequest, e.getCardResponse());
        throw ReaderIOException(MSG_SAM_READER_COMMUNICATION_ERROR + 
                                MSG_WHILE_TRANSMITTING_COMMANDS + 
                                getTransactionAuditDataAsString(),
                                e);

    } catch (const CardBrokenCommunicationException& e) {
        saveTransactionAuditData(cardRequest, e.getCardResponse());
        throw SamIOException(MSG_SAM_COMMUNICATION_ERROR + 
                             MSG_WHILE_TRANSMITTING_COMMANDS + 
                             getTransactionAuditDataAsString(),
                             e);
    
    } catch (const UnexpectedStatusWordException& e) {
        mLogger->debug("A SAM command has failed: %\n", e.getMessage());
        cardResponse = e.getCardResponse();
    }
    
    saveTransactionAuditData(cardRequest, cardResponse);
    
    return cardResponse;
}

void CommonSamTransactionManagerAdapter::prepareSelectDiversifierIfNeeded(
    const std::vector<uint8_t>& specificKeyDiversifier)
{
    if (!specificKeyDiversifier.empty()) {
        if (!Arrays::equals(specificKeyDiversifier, mCurrentKeyDiversifier)) {
            mCurrentKeyDiversifier = specificKeyDiversifier;
            prepareSelectDiversifier();
        }
    } else {
        prepareSelectDiversifierIfNeeded();
    }
}

void CommonSamTransactionManagerAdapter::prepareSelectDiversifierIfNeeded() 
{
    if (!Arrays::equals(mCurrentKeyDiversifier, defaultKeyDiversifier)) {
        mCurrentKeyDiversifier = defaultKeyDiversifier;
        prepareSelectDiversifier();
    }
}

void CommonSamTransactionManagerAdapter::prepareSelectDiversifier() 
{
    mSamCommands.push_back(std::make_shared<CmdSamSelectDiversifier>(mSam->getProductType(), 
                                                                     mCurrentKeyDiversifier));
}

}
}
}
