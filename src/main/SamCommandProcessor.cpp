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

#include "SamCommandProcessor.h"

/* Calypsonet Terminal Calypso */
#include "InconsistentDataException.h"

/* Calypsonet Terminal Card */
#include "CardBrokenCommunicationException.h"
#include "CardSecuritySettingAdapter.h"
#include "ChannelControl.h"
#include "ReaderBrokenCommunicationException.h"
#include "UnexpectedStatusWordException.h"

/* Keyple Card Calypso */
#include "ApduRequestSpi.h"
#include "CardTransactionManagerAdapter.h"
#include "CmdSamCardCipherPin.h"
#include "CmdSamCardGenerateKey.h"
#include "CmdSamDigestAuthenticate.h"
#include "CmdSamDigestClose.h"
#include "CmdSamDigestInit.h"
#include "CmdSamDigestUpdate.h"
#include "CmdSamGetChallenge.h"
#include "CmdSamGiveRandom.h"
#include "CmdSamSelectDiversifier.h"
#include "CmdSamSvCheck.h"
#include "CmdSamSvPrepareDebitOrUndebit.h"
#include "CmdSamSvPrepareLoad.h"

/* Keyple Card Generic */
#include "CardRequestAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "IllegalStateException.h"
#include "KeypleAssert.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const uint8_t SamCommandProcessor::KIF_UNDEFINED = 0xFF;
const uint8_t SamCommandProcessor::CHALLENGE_LENGTH_REV_INF_32 = 0x04;
const uint8_t SamCommandProcessor::CHALLENGE_LENGTH_REV32 = 0x08;
const uint8_t SamCommandProcessor::SIGNATURE_LENGTH_REV_INF_32 = 0x04;
const uint8_t SamCommandProcessor::SIGNATURE_LENGTH_REV32 = 0x08;
const std::string SamCommandProcessor::UNEXPECTED_EXCEPTION = "An unexpected exception was raised.";
std::vector<std::vector<uint8_t>> SamCommandProcessor::mCardDigestDataCache;

SamCommandProcessor::SamCommandProcessor(
  const std::shared_ptr<CalypsoCardAdapter> card,
  const std::shared_ptr<CardSecuritySettingAdapter> securitySetting,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
: mSecuritySetting(securitySetting),
  mCard(card),
  mIsDiversificationDone(false),
  mTransactionAuditData(transactionAuditData)
{
    Assert::getInstance().notNull(securitySetting, "securitySettings")
                         .notNull(securitySetting->getControlSamReader(), "controlSamReader")
                         .notNull(securitySetting->getControlSam(), "controlSam");

    const auto sam = securitySetting->getControlSam();
    mSamProductType = sam->getProductType();
    mSamSerialNumber = sam->getSerialNumber();
    mSamReader = sam->getControlSamReader();
}

const std::vector<uint8_t> SamCommandProcessor::getChallenge()
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;

    /* Diversify only if this has not already been done */
    if (!mIsDiversificationDone) {
        /*
         * Build the "Select Diversifier" SAM command to provide the SAM with the card S/N
         * CL-SAM-CSN.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamSelectDiversifier>(mSamProductType,
                                                      mCard->getCalypsoSerialNumberFull()));

        /* Note that the diversification has been made */
        mIsDiversificationDone = true;
    }

    /* Build the "Get Challenge" SAM command */
    const uint8_t challengeLength = mCard->isExtendedModeSupported() ?
                                    CHALLENGE_LENGTH_REV32 : CHALLENGE_LENGTH_REV_INF_32;
    auto cmdSamGetChallenge = std::make_shared<CmdSamGetChallenge>(mSamProductType,challengeLength);
    samCommands.push_back(cmdSamGetChallenge);

    /* Transmit the commands to the SAM */
    transmitCommands(samCommands);

    /* Retrieve the SAM challenge */
    const std::vector<uint8_t> samChallenge = cmdSamGetChallenge->getChallenge();
    mLogger->debug("identification: TERMINALCHALLENGE=%\n", ByteArrayUtil::toHex(samChallenge));

    return samChallenge;
}

const std::shared_ptr<uint8_t> SamCommandProcessor::computeKvc(
    const WriteAccessLevel writeAccessLevel, const std::shared_ptr<uint8_t> kvc) const
{
    if (kvc != nullptr) {
        return kvc;
    }

    return mSecuritySetting->getDefaultKvc(writeAccessLevel);
}

const std::shared_ptr<uint8_t> SamCommandProcessor::computeKif(
    const WriteAccessLevel writeAccessLevel,
    const std::shared_ptr<uint8_t> kif,
    const std::shared_ptr<uint8_t> kvc)
{
    /* CL-KEY-KIF.1 */
    if ((kif != nullptr && *kif.get() != KIF_UNDEFINED) || (kvc == nullptr)) {
        return kif;
    }

    /* CL-KEY-KIFUNK.1 */
    std::shared_ptr<uint8_t> result = mSecuritySetting->getKif(writeAccessLevel, *kvc.get());
    if (result == nullptr) {
        result = mSecuritySetting->getDefaultKif(writeAccessLevel);
    }

    return result;
}

void SamCommandProcessor::initializeDigester(const bool isSessionEncrypted,
                                             const bool isVerificationMode,
                                             const uint8_t kif,
                                             const uint8_t kvc,
                                             const std::vector<uint8_t>& digestData)
{
    mIsSessionEncryption = isSessionEncrypted;
    mIsVerificationMode = isVerificationMode;
    mKif = kif;
    mKvc = kvc;

    mLogger->debug("initialize: CARDREVISION=%, SAMREVISION=%, SESSIONENCRYPTION=%, " \
                   "VERIFICATIONMODE=%\n",
                   mCard->getProductType(),
                   mSamProductType,
                   isSessionEncryption,
                   isVerificationMode);
    mLogger->debug("initialize: VERIFICATIONMODE=%, REV32MODE=%\n",
                   isVerificationMode,
                   mCard->isExtendedModeSupported());
    mLogger->debug("initialize: KIF=%, KVC=%, DIGESTDATA=%\n",
                   kif,
                   kvc,
                   ByteArrayUtil::toHex(digestData));

    /* Clear data cache */
    mCardDigestDataCache.clear();

    /* Build Digest Init command as first ApduRequestAdapter of the digest computation process */
    mCardDigestDataCache.push_back(digestData);

    mIsDigestInitDone = false;
    mIsDigesterInitialized = true;
}

void SamCommandProcessor::pushCardExchangedData(const std::shared_ptr<ApduRequestSpi> request,
                                                const std::shared_ptr<ApduResponseApi> response)
{
    mLogger->trace("pushCardExchangedData: %\n", request);

    /*
     * Add an ApduRequestAdapter to the digest computation: if the request is of case4 type, Le must
     * be excluded from the digest computation. In this cas, we remove here the last byte of the
     * command buffer.
     * CL-C4-MAC.1
     */
    if (ApduUtil::isCase4(request->getApdu())) {
        mCardDigestDataCache.push_back(
            Arrays::copyOfRange(request->getApdu(), 0, request->getApdu().size() - 1));
    } else {
        mCardDigestDataCache.push_back(request->getApdu());
    }

    mLogger->trace("pushCardExchangedData: %\n", response);

    /* Add an ApduResponseApi to the digest computation */
    mCardDigestDataCache.push_back(response->getApdu());
}

void SamCommandProcessor::pushCardExchangedData(
    const std::vector<std::shared_ptr<ApduRequestSpi>>& requests,
    const std::vector<std::shared_ptr<ApduResponseApi>>& responses,
    const int startIndex)
{
    for (int i = startIndex; i < static_cast<int>(requests.size()); i++) {
        /* Add requests and responses to the digest processor */
        pushCardExchangedData(requests[i], responses[i]);
    }
}

const std::vector<std::shared_ptr<AbstractSamCommand>> SamCommandProcessor::getPendingSamCommands(
    const bool addDigestClose)
{
    /* TODO optimization with the use of Digest Update Multiple whenever possible */
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;

    /* Sanity checks */
    if (mCardDigestDataCache.empty()) {
        mLogger->debug("getSamDigestRequest: no data in cache\n");
        throw IllegalStateException("Digest data cache is empty.");
    }

    if (!mIsDigestInitDone && mCardDigestDataCache.size() % 2 == 0) {
        /* The number of buffers should be 2*n + 1 */
        mLogger->debug("getSamDigestRequest: wrong number of buffer in cache NBR = %\n",
                       mCardDigestDataCache.size());
        throw IllegalStateException("Digest data cache is inconsistent.");
    }

    if (!mIsDigestInitDone) {
        /*
         * Build and append Digest Init command as first ApduRequestAdapter of the digest
         * computation process. The Digest Init command comes from the Open Secure Session response
         * from the card. Once added to the ApduRequestAdapter list, the data is remove from the
         * cache to keep only couples of card request/response
         * CL-SAM-DINIT.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamDigestInit>(mSamProductType,
                                               mIsVerificationMode,
                                               mCard->isExtendedModeSupported(),
                                               mKif,
                                               mKvc,
                                               mCardDigestDataCache[0]));
        mCardDigestDataCache.erase(mCardDigestDataCache.begin());

        /* Note that the digest init has been made */
        mIsDigestInitDone = true;
    }

    /*
     * Build and append Digest Update commands
     * CL-SAM-DUPDATE.1
     */
    for (const auto& bytes : mCardDigestDataCache) {
        samCommands.push_back(
            std::make_shared<CmdSamDigestUpdate>(mSamProductType, mIsSessionEncrypted, bytes));
    }

    /* Clears cached commands once they have been processed */
    mCardDigestDataCache.clear();

    if (addDigestClose) {
        /*
         * Build and append Digest Close command
         * CL-SAM-DCLOSE.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamDigestClose>(mSamProductType,
                                                mCard->isExtendedModeSupported() ?
                                                SIGNATURE_LENGTH_REV32 :
                                                SIGNATURE_LENGTH_REV_INF_32));
    }

    return samCommands;
}

const std::vector<uint8_t> SamCommandProcessor::getTerminalSignature()
{
    /*
     * All remaining SAM digest operations will now run at once.
     * Get the SAM Digest request including Digest Close from the cache manager
     */
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands = getPendingSamCommands(true);

    /* Transmit the commands to the SAM */
    transmitCommands(samCommands);

    /* Get Terminal Signature from the latest response */
    const std::vector<uint8_t> terminalSignature =
        std::dynamic_pointer_cast<CmdSamDigestClose>(samCommands[samCommands.size() - 1])
            ->getSignature();

    mLogger->debug("SIGNATURE=%\n", ByteArrayUtil::toHex(terminalSignature));

    return terminalSignature;
}

const std::vector<std::shared_ptr<ApduRequestSpi>> SamCommandProcessor::getApduRequests(
    const std::vector<std::shared_ptr<AbstractSamCommand>> samCommands) const
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    if (!samCommands.empty()) {
        for (const auto& samCommand : samCommands) {
            apduRequests.push_back(samCommand->getApduRequest());
        }
    }

    return apduRequests;
}

void SamCommandProcessor::transmitCommands(
    const std::vector<std::shared_ptr<AbstractSamCommand>>& samCommands)
{
    const std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests = getApduRequests(samCommands);
    auto cardRequest = std::make_shared<CardRequestAdapter>(apduRequests, true);
    std::shared_ptr<CardResponseApi> cardResponse = nullptr;

    try {
        cardResponse = mSamReader->transmitCardRequest(cardRequest, ChannelControl::KEEP_OPEN);
    } catch (const ReaderBrokenCommunicationException& e) {
        cardResponse = e.getCardResponse();
        throw e;
    } catch (const CardBrokenCommunicationException& e) {
        cardResponse = e.getCardResponse();
        throw e;
    } catch (const UnexpectedStatusWordException& e) {
        mLogger->debug("A SAM card command has failed: %\n", e.getMessage());
        cardResponse = e.getCardResponse();
    }

    CardTransactionManagerAdapter::saveTransactionAuditData(cardRequest, 
                                                            cardResponse, 
                                                            mTransactionAuditData);

    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponses = 
        cardResponse->getApduResponses();

    /*
     * If there are more responses than requests, then we are unable to fill the card image. In this
     * case we stop processing immediately because it may be a case of fraud, and we throw a
     * desynchronized exception.
     */
    if (apduResponses.size() > apduRequests.size()) {
        throw InconsistentDataException("The number of SAM commands/responses does not " \
                                        "match: nb commands = " +
                                        std::to_string(apduRequests.size()) + 
                                        ", nb responses = " + 
                                        std::to_string(apduResponses.size()));
    }

    /*
     * We go through all the responses (and not the requests) because there may be fewer in the case
     * of an error that occurred in strict mode. In this case the last response will raise an
     * exception.
     */
    for (int i = 0; i < static_cast<int>(apduResponses.size()); i++) {
        samCommands[i]->setApduResponse(apduResponses[i]).checkStatus();
    }

    /*
     * Finally, if no error has occurred and there are fewer responses than requests, then we
     * throw a desynchronized exception.
     */
    if (apduResponses.size() < apduRequests.size()) {
        throw InconsistentDataException("The number of SAM commands/responses does not " \
                                        "match: nb commands = " + 
                                        std::to_string(apduRequests.size()) +
                                        ", nb responses = " + 
                                        std::to_string(apduResponses.size()));
    }
}

void SamCommandProcessor::authenticateCardSignature(const std::vector<uint8_t>& cardSignatureLo)
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands(1);
    samCommands.push_back(
        std::make_shared<CmdSamDigestAuthenticate>(mSamProductType, cardSignatureLo));

    transmitCommands(samCommands);
}

const std::vector<uint8_t> SamCommandProcessor::getEncryptedKey(
    const std::vector<uint8_t>& cardChallenge,
    const uint8_t cipheringKif,
    const uint8_t cipheringKvc,
    const uint8_t sourceKif,
    const uint8_t sourceKvc)
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;

    if (!mIsDiversificationDone) {
        /*
         * Build the SAM Select Diversifier command to provide the SAM with the card S/N
         * CL-SAM-CSN.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamSelectDiversifier>(mSamProductType,
                                                      mCard->getCalypsoSerialNumberFull()));
        mIsDiversificationDone = true;
    }

    samCommands.push_back(std::make_shared<CmdSamGiveRandom>(mSamProductType, cardChallenge));

    auto cmdSamCardGenerateKey = std::make_shared<CmdSamCardGenerateKey>(mSamProductType,
                                                                         cipheringKif,
                                                                         cipheringKvc,
                                                                         sourceKif,
                                                                         sourceKvc);

    samCommands.push_back(cmdSamCardGenerateKey);

    /* Transmit the commands to the SAM */
    transmitCommands(samCommands);

    return cmdSamCardGenerateKey->getCipheredData();
}

const std::vector<uint8_t> SamCommandProcessor::getCipheredPinData(
    const std::vector<uint8_t>& cardChallenge,
    const std::vector<uint8_t>& currentPin,
    const std::vector<uint8_t>& newPin)
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;
    uint8_t pinCipheringKif;
    uint8_t pinCipheringKvc;

    if (mKif != 0) {
        /* The current work key has been set (a secure session is open) */
        pinCipheringKif = mKif;
        pinCipheringKvc = mKvc;
    } else {
        /* No current work key is available (outside secure session) */
        if (newPin.empty()) {
            /* PIN verification */

            if (mSecuritySetting->getPinVerificationCipheringKif() == nullptr ||
                mSecuritySetting->getPinVerificationCipheringKvc() == nullptr) {
                throw IllegalStateException("No KIF or KVC defined for the PIN verification " \
                                            "ciphering key");
            }

            pinCipheringKif = *mSecuritySetting->getPinVerificationCipheringKif();
            pinCipheringKvc = *mSecuritySetting->getPinVerificationCipheringKvc();
        } else {
            /* PIN modification */
            if (mSecuritySetting->getPinModificationCipheringKif() == nullptr ||
                mSecuritySetting->getPinModificationCipheringKvc() == nullptr) {
                throw IllegalStateException("No KIF or KVC defined for the PIN modification " \
                                            "ciphering key");
            }

            pinCipheringKif = *mSecuritySetting->getPinModificationCipheringKif();
            pinCipheringKvc = *mSecuritySetting->getPinModificationCipheringKvc();
        }
    }

    if (!mIsDiversificationDone) {
        /*
         * Build the SAM Select Diversifier command to provide the SAM with the card S/N
         * CL-SAM-CSN.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamSelectDiversifier>(mSamProductType,
                                                      mCard->getCalypsoSerialNumberFull()));
        mIsDiversificationDone = true;
    }

    if (mIsDigesterInitialized) {
        /*
         * Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list
         */
        Arrays::addAll(samCommands, getPendingSamCommands(false));
    }

    samCommands.push_back(std::make_shared<CmdSamGiveRandom>(mSamProductType, cardChallenge));

    auto cmdSamCardCipherPin = std::make_shared<CmdSamCardCipherPin>(mSamProductType,
                                                                     pinCipheringKif,
                                                                     pinCipheringKvc,
                                                                     currentPin,
                                                                     newPin);

    samCommands.push_back(cmdSamCardCipherPin);

    transmitCommands(samCommands);

    return cmdSamCardCipherPin->getCipheredData();
}

const std::vector<uint8_t> SamCommandProcessor::getSvComplementaryData(
    const std::shared_ptr<AbstractSamCommand> cmdSamSvPrepare)
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;

    if (!mIsDiversificationDone) {
        /*
         * Build the SAM Select Diversifier command to provide the SAM with the card S/N
         * CL-SAM-CSN.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamSelectDiversifier>(mSamProductType,
                                                      mCard->getCalypsoSerialNumberFull()));
        mIsDiversificationDone = true;
    }

    if (mIsDigesterInitialized) {
        /*
         * Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list
         */
        Arrays::addAll(samCommands, getPendingSamCommands(false));
    }

    samCommands.push_back(cmdSamSvPrepare);

    transmitCommands(samCommands);

    std::vector<uint8_t> prepareOperationData = cmdSamSvPrepare->getApduResponse()->getDataOut();
    std::vector<uint8_t> operationComplementaryData(mSamSerialNumber.size() + prepareOperationData.size());

    System::arraycopy(mSamSerialNumber, 0, operationComplementaryData, 0, mSamSerialNumber.size());
    System::arraycopy(prepareOperationData,
                      0,
                      operationComplementaryData,
                      mSamSerialNumber.size(),
                      prepareOperationData.size());

    return operationComplementaryData;
}

const std::vector<uint8_t> SamCommandProcessor::getSvReloadComplementaryData(
    const std::shared_ptr<CmdCardSvReload> cmdCardSvReload,
    const std::vector<uint8_t>& svGetHeader,
    const std::vector<uint8_t>& svGetData)
{
    const auto cmdSamSvPrepareLoad =
        std::make_shared<CmdSamSvPrepareLoad>(mSamProductType,
                                              svGetHeader,
                                              svGetData,
                                              cmdCardSvReload->getSvReloadData());

    return getSvComplementaryData(cmdSamSvPrepareLoad);
}

const std::vector<uint8_t> SamCommandProcessor::getSvDebitOrUndebitComplementaryData(
    const bool isDebitCommand,
    const std::shared_ptr<CmdCardSvDebitOrUndebit> cmdCardSvDebitOrUndebit,
    const std::vector<uint8_t>& svGetHeader,
    const std::vector<uint8_t>& svGetData)
{
    const auto cmdSamSvPrepareDebitOrUndebit =
        std::make_shared<CmdSamSvPrepareDebitOrUndebit>(isDebitCommand,
                                                        mSamProductType,
                                                        svGetHeader,
                                                        svGetData,
                                                        cmdCardSvDebitOrUndebit->getSvDebitOrUndebitData());

    return getSvComplementaryData(cmdSamSvPrepareDebitOrUndebit);
}

void SamCommandProcessor::checkSvStatus(const std::vector<uint8_t>& svOperationResponseData)
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;
    samCommands.push_back(
        std::make_shared<CmdSamSvCheck>(mSamProductType, svOperationResponseData));
    
    transmitCommands(samCommands);
}

}
}
}
