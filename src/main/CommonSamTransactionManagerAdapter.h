/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
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
#include "InconsistentDataException.h"
#include "InvalidCardSignatureException.h"
#include "InvalidSignatureException.h"
#include "ReaderIOException.h"
#include "SamIOException.h"
#include "SamRevokedException.h"
#include "UnexpectedCommandStatusException.h"

/* Calypsonet Terminal Card */
#include "ProxyReaderApi.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "BasicSignatureComputationDataAdapter.h"
#include "CalypsoSamAdapter.h"
#include "CalypsoSamSecurityDataException.h"
#include "CalypsoSamCommandException.h"
#include "CardBrokenCommunicationException.h"
#include "CardRequestAdapter.h"
#include "CmdSamDataCipher.h"
#include "CmdSamPsoComputeSignature.h"
#include "CmdSamPsoVerifySignature.h"
#include "CmdSamSelectDiversifier.h"
#include "CommonSecuritySettingAdapter.h"
#include "CommonSignatureComputationData.h"
#include "CommonSignatureVerificationData.h"
#include "CommonTransactionManagerAdapter.h"
#include "ReaderBrokenCommunicationException.h"
#include "SamSecuritySetting.h"
#include "SamSecuritySettingAdapter.h"
#include "SamTransactionManager.h"
#include "TraceableSignatureComputationDataAdapter.h"
#include "TraceableSignatureVerificationDataAdapter.h"
#include "UnexpectedStatusWordException.h"

/* Keyple Core Util */
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "HexUtil.h"
#include "KeypleAssert.h"
#include "KeypleStd.h"
#include "LoggerFactory.h"
#include "StringUtils.h"
#include "UnsupportedOperationException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

/**
 * (package-private)<br>
 * Abstract class for all SamTransactionManager classes.
 *
 * @since 2.2.0
 */
template <typename T>
class CommonSamTransactionManagerAdapter
: public CommonTransactionManagerAdapter<SamTransactionManager,
                                         CommonSecuritySetting,
                                         CommonSecuritySetting>,
  public SamTransactionManager {
public:
    /**
     * (package-private)<br>
     * Creates a new instance (to be used for instantiation of SamTransactionManagerAdapter
     * only).
     *
     * @param samReader The reader through which the SAM communicates.
     * @param sam The initial SAM data provided by the selection process.
     * @param securitySetting The SAM security settings (optional).
     * @since 2.2.0
     */
    CommonSamTransactionManagerAdapter(
        const std::shared_ptr<ProxyReaderApi> samReader,
        const std::shared_ptr<CalypsoSamAdapter> sam,
        const std::shared_ptr<SamSecuritySettingAdapter> securitySetting)
    : CommonTransactionManagerAdapter(
      sam,
      securitySetting,
      std::vector<std::vector<uint8_t>>()),
      mSamReader(samReader),
      mSam(sam),
      mSecuritySetting(securitySetting),
      mDefaultKeyDiversifier(sam->getSerialNumber()) {}

    /**
     * (package-private)<br>
     * Creates a new instance (to be used for instantiation of
     * CommonControlSamTransactionManagerAdapter only).
     *
     * @param targetSmartCard The target smartcard provided by the selection process.
     * @param securitySetting The card or SAM security settings.
     * @param defaultKeyDiversifier The full serial number of the target card or SAM to be used by
     *     default when diversifying keys.
     * @param transactionAuditData The original transaction data to fill.
     * @since 2.2.0
     */
    CommonSamTransactionManagerAdapter(
        const std::shared_ptr<SmartCard> targetSmartCard,
        const std::shared_ptr<CommonSecuritySettingAdapter<T>> securitySetting,
        const std::vector<uint8_t>& defaultKeyDiversifier,
        const std::vector<std::vector<uint8_t>>& transactionAuditData)
    : CommonTransactionManagerAdapter(
      targetSmartCard,
      securitySetting,
      transactionAuditData),
      mSamReader(securitySetting->getControlSamReader()),
      mSam(securitySetting->getControlSam()),
      mSecuritySetting(securitySetting),
      mDefaultKeyDiversifier(defaultKeyDiversifier) {}

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
     * @since 2.2.0
     */
    const std::shared_ptr<CardReader> getSamReader() const final
    {
        return std::dynamic_pointer_cast<CardReader>(mSamReader);
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<CalypsoSam> getCalypsoSam() const final
    {
        return mSam;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& prepareComputeSignature(const any data) override
    {
        /* C++: careful, code is a little bit different from Java because of any_cast flow */
        try {

            /* Basic signature */
            auto dataAdapter =
                any_cast<std::shared_ptr<BasicSignatureComputationDataAdapter>>(data);

            Assert::getInstance().notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
                                 .isInRange(dataAdapter->getData().size(),
                                            1,
                                            208,
                                            "length of data to sign")
                                 .isTrue(dataAdapter->getData().size() % 8 == 0,
                                         "length of data to sign is a multiple of 8")
                                 .isInRange(dataAdapter->getSignatureSize(),
                                            1,
                                            8,
                                            MSG_SIGNATURE_SIZE)
                                 .isTrue(dataAdapter->isKeyDiversifierSet() == false ||
                                         (dataAdapter->getKeyDiversifier().size() >= 1 &&
                                          dataAdapter->getKeyDiversifier().size() <= 8),
                                         MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

            prepareSelectDiversifierIfNeeded(dataAdapter->getKeyDiversifier());
            mSamCommands.push_back(std::make_shared<CmdSamDataCipher>(mSam, dataAdapter, nullptr));

            return *this;

        } catch (const std::exception& e) {

            (void)e;
        }

        try {

            /* Traceable signature */
            auto dataAdapter =
                any_cast<std::shared_ptr<TraceableSignatureComputationDataAdapter>>(data);

            Assert::getInstance().notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
                                .isInRange(dataAdapter->getData().size(),
                                            1,
                                            dataAdapter->isSamTraceabilityMode() ? 206 : 208,
                                            "length of data to sign")
                                .isInRange(dataAdapter->getSignatureSize(),
                                           1,
                                           8,
                                           MSG_SIGNATURE_SIZE)
                                .isTrue(!dataAdapter->isSamTraceabilityMode() ||
                                        (dataAdapter->getTraceabilityOffset() >= 0 &&
                                         dataAdapter->getTraceabilityOffset() <=
                                            static_cast<int>((dataAdapter->getData().size() * 8) -
                                            (dataAdapter->isPartialSamSerialNumber() ?
                                            7 * 8 : 8 * 8))),
                                        "traceability offset is in range [0.." +
                                        std::to_string(((dataAdapter->getData().size() * 8) -
                                                        (dataAdapter->isPartialSamSerialNumber() ? 7 * 8 : 8 * 8))) +
                                        "]")
                                .isTrue(dataAdapter->isKeyDiversifierSet() == false ||
                                        (dataAdapter->getKeyDiversifier().size() >= 1 &&
                                         dataAdapter->getKeyDiversifier().size() <= 8),
                                        MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

                prepareSelectDiversifierIfNeeded(dataAdapter->getKeyDiversifier());
                mSamCommands.push_back(
                    std::make_shared<CmdSamPsoComputeSignature>(mSam, dataAdapter));

                return *this;

        } catch (const std::exception& e) {

            (void)e;
        }

        throw IllegalArgumentException("The provided data must be an instance of " \
                                       "'BasicSignatureComputationDataAdapter' or " \
                                       "'TraceableSignatureComputationDataAdapter'");
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& prepareVerifySignature(const any data) override
    {
        /* C++: careful, code is a little bit different from Java because of any_cast flow */
        try {

            /* Basic signature */
            auto dataAdapter =
                any_cast<std::shared_ptr<BasicSignatureVerificationDataAdapter>>(data);

            Assert::getInstance().notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
                                 .isInRange(dataAdapter->getData().size(),
                                            1,
                                            208,
                                            "length of signed data to verify")
                                 .isTrue(dataAdapter->getData().size() % 8 == 0,
                                         "length of data to verify is a multiple of 8")
                                 .isInRange(dataAdapter->getSignature().size(),
                                            1,
                                            8,
                                            MSG_SIGNATURE_SIZE)
                                 .isTrue(dataAdapter->isKeyDiversifierSet() == false ||
                                         (dataAdapter->getKeyDiversifier().size() >= 1 &&
                                          dataAdapter->getKeyDiversifier().size() <= 8),
                                         MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

            prepareSelectDiversifierIfNeeded(dataAdapter->getKeyDiversifier());
            mSamCommands.push_back(
                std::make_shared<CmdSamDataCipher>(mSam, nullptr, dataAdapter));

            return *this;

        } catch (const std::exception& e) {

            (void)e;
        }

        try {

            /* Traceable signature */
            auto dataAdapter =
                any_cast<std::shared_ptr<TraceableSignatureVerificationDataAdapter>>(data);

            Assert::getInstance().notNull(dataAdapter, MSG_INPUT_OUTPUT_DATA)
                                 .isInRange(dataAdapter->getData().size(),
                                            1,
                                            dataAdapter->isSamTraceabilityMode() ? 206 : 208,
                                            "length of signed data to verify")
                                 .isInRange(dataAdapter->getSignature().size(),
                                            1,
                                            8,
                                            MSG_SIGNATURE_SIZE)
                                 .isTrue(!dataAdapter->isSamTraceabilityMode() ||
                                         (dataAdapter->getTraceabilityOffset() >= 0 &&
                                          dataAdapter->getTraceabilityOffset() <=
                                             static_cast<int>((dataAdapter->getData().size() * 8) -
                                                              (dataAdapter->isPartialSamSerialNumber() ?
                                                              7 * 8 : 8 * 8))),
                                         "traceability offset is in range [0.." +
                                         std::to_string((dataAdapter->getData().size() * 8) -
                                                         (dataAdapter->isPartialSamSerialNumber() ? 7 * 8 : 8 * 8)) +
                                         "]")
                                 .isTrue(dataAdapter->isKeyDiversifierSet() == false ||
                                         (dataAdapter->getKeyDiversifier().size() >= 1 &&
                                          dataAdapter->getKeyDiversifier().size() <= 8),
                                         MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8);

            /* Check SAM revocation status if requested. */
            if (dataAdapter->isSamRevocationStatusVerificationRequested()) {

                Assert::getInstance().notNull(mSecuritySetting, "security settings")
                                     .notNull(mSecuritySetting->getSamRevocationServiceSpi(),
                                             "SAM revocation service");

                /* Extract the SAM serial number and the counter value from the data. */
                const std::vector<uint8_t> samSerialNumber =
                    ByteArrayUtil::extractBytes(dataAdapter->getData(),
                                                dataAdapter->getTraceabilityOffset(),
                                                dataAdapter->isPartialSamSerialNumber() ? 3 : 4);

                const int samCounterValue =
                    ByteArrayUtil::extractInt(
                        ByteArrayUtil::extractBytes(dataAdapter->getData(),
                                                    dataAdapter->getTraceabilityOffset() +
                                                    (dataAdapter->isPartialSamSerialNumber() ?
                                                        3 * 8 : 4 * 8),
                                                    3),
                        0,
                        3,
                        false);

                /* Is SAM revoked ? */
                if (mSecuritySetting->getSamRevocationServiceSpi()
                                    ->isSamRevoked(samSerialNumber, samCounterValue)) {

                    throw SamRevokedException(
                            StringUtils::format("SAM with serial number '%s' and counter value '%d' " \
                                                "is revoked.",
                                                HexUtil::toHex(samSerialNumber).c_str(),
                                                samCounterValue));
                }
            }

            prepareSelectDiversifierIfNeeded(dataAdapter->getKeyDiversifier());
            mSamCommands.push_back(
                std::make_shared<CmdSamPsoVerifySignature>(mSam, dataAdapter));

                return *this;

        } catch (const std::bad_cast& e) {

            /* C++: Fall through... */
            (void)e;

        } catch (const Exception& e) {

            /* C++: rethrow since we are in a try/catch block */
            (void)e;
            throw;
        }

        throw IllegalArgumentException("The provided data must be an instance of " \
                                       "'CommonSignatureVerificationDataAdapter'");
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& processCommands() override
    {
        if (mSamCommands.empty()) {

            return *this;
        }

        try {

            /* Get the list of C-APDU to transmit */
            const std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests =
                getApduRequests(mSamCommands);

            /* Wrap the list of C-APDUs into a card request */
            auto cardRequest = std::make_shared<CardRequestAdapter>(apduRequests, true);

            /* Transmit the commands to the SAM */
            const std::shared_ptr<CardResponseApi> cardResponse = transmitCardRequest(cardRequest);

            /* Retrieve the list of R-APDUs */
            const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses =
                cardResponse->getApduResponses();

            /*
            * If there are more responses than requests, then we are unable to fill the card image.
            * In this case we stop processing immediately because it may be a case of fraud, and we
            * throw an exception.
            */
            if (apduResponses.size() > apduRequests.size()) {

                throw InconsistentDataException("The number of SAM commands/responses does not " \
                                                "match: nb commands = " +
                                                std::to_string(apduRequests.size()) +
                                                ", nb responses = " +
                                                std::to_string(apduResponses.size()) +
                                                getTransactionAuditDataAsString());
            }

            /*
            * We go through all the responses (and not the requests) because there may be fewer in
            * the case of an error that occurred in strict mode. In this case the last response will
            * raise an exception.
            */
            for (int i = 0; i < static_cast<int>(apduResponses.size()); i++) {

                try {

                    mSamCommands[i]->parseApduResponse(apduResponses[i]);

                } catch (const Exception& ex) {

                    /*
                     * C++: for some reason, it doesn't work if trying to catch directly the
                     * CalypsoSamCommandException exception.
                     */
                    const CalypsoSamCommandException &e =
                        dynamic_cast<const CalypsoSamCommandException&>(ex);

                    try {

                        const CalypsoSamCommand& commandRef =
                            std::dynamic_pointer_cast<AbstractSamCommand>(mSamCommands[i])
                                ->getCommandRef();

                        if (commandRef == CalypsoSamCommand::DIGEST_AUTHENTICATE) {

                            /* C++: cast made outside the if/else condition, will throw if false */
                            (void)static_cast<const CalypsoSamSecurityDataException&>(e);
                            throw InvalidCardSignatureException(
                                    "Invalid card signature.",
                                    std::make_shared<CalypsoSamCommandException>(e));

                        } else if (commandRef == CalypsoSamCommand::PSO_VERIFY_SIGNATURE ||
                                   commandRef == CalypsoSamCommand::DATA_CIPHER) {

                            /* C++: cast made outside the if/else condition, will throw if false */
                            (void)static_cast<const CalypsoSamSecurityDataException&>(e);
                            throw InvalidSignatureException(
                                    "Invalid signature.",
                                    std::make_shared<CalypsoSamSecurityDataException>(
                                        e.getMessage(),
                                        dynamic_cast<const CalypsoSamCommand&>(e.getCommand()),
                                        e.getStatusWord()));

                        } else if (commandRef == CalypsoSamCommand::SV_CHECK) {

                            /* C++: cast made outside the if/else condition, will throw if false */
                            (void)static_cast<const CalypsoSamSecurityDataException&>(e);
                            throw InvalidCardSignatureException(
                                    "Invalid SV card signature.",
                                    std::make_shared<CalypsoSamSecurityDataException>(
                                        e.getMessage(),
                                        dynamic_cast<const CalypsoSamCommand&>(e.getCommand()),
                                        e.getStatusWord()));
                        }

                    } catch (const std::bad_cast& e) {

                        /* C++: Fall through... */
                        (void)e;

                    } catch (const Exception& e) {

                        /* C++: need to rethrow as we are in a try/catch block */
                        (void)e;
                        throw;
                    }

                    throw UnexpectedCommandStatusException(
                              MSG_SAM_COMMAND_ERROR +
                              "while processing responses to SAM commands: " +
                              e.getCommand().getName() +
                              getTransactionAuditDataAsString(),
                              std::make_shared<CalypsoSamCommandException>(e));
                }
            }

            /*
            * Finally, if no error has occurred and there are fewer responses than requests, then we
            * throw an exception.
            */
            if (apduResponses.size() < apduRequests.size()) {

                throw InconsistentDataException(
                          "The number of SAM commands/responses does not match:" \
                          " nb commands = " + std::to_string(apduRequests.size()) +
                          ", nb responses = " + std::to_string(apduResponses.size()) +
                          getTransactionAuditDataAsString());
            }

        } catch (const Exception& e) {

            /* C++: need to rethrow as we are in a try/catch block */
            (void)e;

            /* Reset the list of commands (finally) */
            mSamCommands.clear();

            throw;
        }

        /* Reset the list of commands (finally) */
        mSamCommands.clear();

        return *this;
    }

protected:
    /**
     * (package-private)<br>
     * Returns a reference to the main list of SAM commands.
     *
     * C++: vector of AbstractApduCommand instead of AbstractCardCommand because of vector
     * vs. polymorphism issues...
     *
     * @since 2.2.0
     */
    virtual std::vector<std::shared_ptr<AbstractApduCommand>>& getSamCommands()
    {
        return mSamCommands;
    }

    /**
     * (package-private)<br>
     * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it
     * is not already selected.
     *
     * @param specificKeyDiversifier The specific key diversifier (optional).
     * @since 2.2.0
     */
    void prepareSelectDiversifierIfNeeded(const std::vector<uint8_t>& specificKeyDiversifier)
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

    /**
     * (package-private)<br>
     * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
     * selected.
     *
     * @since 2.2.0
     */
    void prepareSelectDiversifierIfNeeded()
    {
        if (!Arrays::equals(mCurrentKeyDiversifier, mDefaultKeyDiversifier)) {
            mCurrentKeyDiversifier = mDefaultKeyDiversifier;
            prepareSelectDiversifier();
        }
    }

    // /**
    //  * {@inheritDoc}
    //  *
    //  * @since 2.2.3
    //  */
    // SamTransactionManager& prepareReadEventCounter(const int eventCounterNumber) override
    // {
    //     throw UnsupportedOperationException("prepareReadEventCounter");
    // }

    // /**
    //  * {@inheritDoc}
    //  *
    //  * @since 2.2.3
    //  */
    // SamTransactionManager& prepareReadEventCounters(const int fromEventCounterNumber,
    //                                                 const int toEventCounterNumber) override
    // {
    //     throw UnsupportedOperationException("prepareReadEventCounters");
    // }

    // /**
    //  * {@inheritDoc}
    //  *
    //  * @since 2.2.3
    //  */
    // SamTransactionManager& prepareReadEventCeiling(const int eventCeilingNumber) override
    // {
    //     throw UnsupportedOperationException("prepareReadEventCeiling");
    // }

    // /**
    //  * {@inheritDoc}
    //  *
    //  * @since 2.2.3
    //  */
    // SamTransactionManager& prepareReadEventCeilings(const int fromEventCeilingNumber,
    //                                                 const int toEventCeilingNumber) override
    // {
    //     throw UnsupportedOperationException("prepareReadEventCeilings");
    // }

    // /**
    //  * {@inheritDoc}
    //  *
    //  * @since 2.2.3
    //  */
    // SamTransactionManager& prepareWriteEventCeiling(const int eventCeilingNumber,
    //                                                 const int newValue) override
    // {
    //     throw UnsupportedOperationException("prepareWriteEventCeiling");
    // }

    // /**
    //  * {@inheritDoc}
    //  *
    //  * @since 2.2.3
    //  */
    // SamTransactionManager& prepareWriteEventCeilings(const int fromEventCeilingNumber,
    //                                                  const std::vector<int>& newValues) override
    // {
    //     throw UnsupportedOperationException("prepareWriteEventCeilings");
    // }

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CommonSamTransactionManagerAdapter));

    const std::string MSG_INPUT_OUTPUT_DATA = "input/output data";
    const std::string MSG_SIGNATURE_SIZE = "signature size";
    const std::string MSG_KEY_DIVERSIFIER_SIZE_IS_IN_RANGE_1_8 =
        "key diversifier size is in range [1..8]";

    /* Final fields */
    const std::shared_ptr<ProxyReaderApi> mSamReader;
    const std::shared_ptr<CalypsoSamAdapter> mSam;
    const std::shared_ptr<CommonSecuritySettingAdapter<CommonSecuritySetting>> mSecuritySetting;

    /*
     * C++: use AbstractApduCommand instead of AbstractSamCommand for vector vs. polymorphism
     * constaints.
     */
    std::vector<std::shared_ptr<AbstractApduCommand>> mSamCommands;
    const std::vector<uint8_t> mDefaultKeyDiversifier;

    /* Dynamic fields */
    std::vector<uint8_t> mCurrentKeyDiversifier;

    /**
     * (private)<br>
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @return The card response.
     */
    virtual std::shared_ptr<CardResponseApi> transmitCardRequest(
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
                                    std::make_shared<ReaderBrokenCommunicationException>(e));

        } catch (const CardBrokenCommunicationException& e) {
            saveTransactionAuditData(cardRequest, e.getCardResponse());
            throw SamIOException(MSG_SAM_COMMUNICATION_ERROR +
                                MSG_WHILE_TRANSMITTING_COMMANDS +
                                getTransactionAuditDataAsString(),
                                std::make_shared<CardBrokenCommunicationException>(e));

        } catch (const UnexpectedStatusWordException& e) {
            mLogger->debug("A SAM command has failed: %\n", e.getMessage());
            cardResponse = e.getCardResponse();
        }

        saveTransactionAuditData(cardRequest, cardResponse);

        return cardResponse;
    }

    /**
     * (private)<br>
     * Prepares a "SelectDiversifier" command using the current key diversifier.
     *
     * @return The current instance.
     */
    virtual void prepareSelectDiversifier()
    {
        mSamCommands.push_back(std::make_shared<CmdSamSelectDiversifier>(mSam,
                                                                         mCurrentKeyDiversifier));
    }
};

}
}
}
