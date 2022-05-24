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
#include "DesynchronizedExchangesException.h"

/* Calypsonet Terminal Card */
#include "CardSecuritySettingAdapter.h"
#include "ChannelControl.h"
#include "UnexpectedStatusWordException.h"

/* Keyple Card Calypso */
#include "ApduRequestSpi.h"
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
#include "CmdSamSvPrepareDebit.h"
#include "CmdSamSvPrepareLoad.h"
#include "CmdSamSvPrepareUndebit.h"

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
using namespace keyple::card::calypso;
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
  const std::shared_ptr<CalypsoCard> calypsoCard,
  const std::shared_ptr<CardSecuritySetting> cardSecuritySetting)
: mCardSecuritySettings(cardSecuritySetting),
  mCalypsoCard(std::dynamic_pointer_cast<CalypsoCardAdapter>(calypsoCard)),
  mIsDiversificationDone(false)
{
    const auto stngs = std::dynamic_pointer_cast<CardSecuritySettingAdapter>(cardSecuritySetting);
    Assert::getInstance().notNull(stngs, "securitySettings")
                         .notNull(stngs->getSamReader(), "samReader")
                         .notNull(stngs->getCalypsoSam(), "calypsoSam");

    const auto calypsoSam = stngs->getCalypsoSam();
    mSamProductType = calypsoSam->getProductType();
    mSamSerialNumber = calypsoSam->getSerialNumber();
    mSamReader = std::dynamic_pointer_cast<ProxyReaderApi>(stngs->getSamReader());
}

const std::vector<uint8_t> SamCommandProcessor::getSessionTerminalChallenge()
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    /* Diversify only if this has not already been done */
    if (!mIsDiversificationDone) {
        /*
         * Build the SAM Select Diversifier command to provide the SAM with the card S/N
         * CL-SAM-CSN.1
         */
        const auto selectDiversifierCmd =
            std::make_shared<CmdSamSelectDiversifier>(mSamProductType,
                                                      mCalypsoCard->getCalypsoSerialNumberFull());

        apduRequests.push_back(selectDiversifierCmd->getApduRequest());

        /* Note that the diversification has been made */
        mIsDiversificationDone = true;
    }

    /* Build the SAM Get Challenge command */
    const uint8_t challengeLength = mCalypsoCard->isExtendedModeSupported() ?
                                    CHALLENGE_LENGTH_REV32 : CHALLENGE_LENGTH_REV_INF_32;

    auto samGetChallengeCmd = std::make_shared<CmdSamGetChallenge>(mSamProductType,challengeLength);

    apduRequests.push_back(samGetChallengeCmd->getApduRequest());

    /* Transmit the CardRequest to the SAM and get back the CardResponse (list of ApduResponseApi)*/
    std::shared_ptr<CardResponseApi> samCardResponse;
    try {
        samCardResponse = mSamReader->transmitCardRequest(
                              std::make_shared<CardRequestAdapter>(apduRequests, false),
                              ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    const std::vector<std::shared_ptr<ApduResponseApi>>&
        samApduResponses = samCardResponse->getApduResponses();
    std::vector<uint8_t> sessionTerminalChallenge;

    const int numberOfSamCmd = apduRequests.size();
    if (static_cast<int>(samApduResponses.size()) == numberOfSamCmd) {
        samGetChallengeCmd->setApduResponse(samApduResponses[numberOfSamCmd - 1]).checkStatus();
        sessionTerminalChallenge = samGetChallengeCmd->getChallenge();
        mLogger->debug("identification: TERMINALCHALLENGE = %\n",
                       ByteArrayUtil::toHex(sessionTerminalChallenge));

    } else {
        throw DesynchronizedExchangesException("The number of commands/responses does not match: " \
                                               "cmd=" + std::to_string(numberOfSamCmd) + ", " +
                                               "resp=" + std::to_string(samApduResponses.size()));
    }

    return sessionTerminalChallenge;
}

const std::shared_ptr<uint8_t> SamCommandProcessor::computeKvc(
    const WriteAccessLevel writeAccessLevel, const std::shared_ptr<uint8_t> kvc) const
{
    if (kvc != nullptr) {
        return kvc;
    }

    return std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings)
               ->getDefaultKvc(writeAccessLevel);
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
    const auto adptr = std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings);
    std::shared_ptr<uint8_t> result = adptr->getKif(writeAccessLevel, *kvc.get());
    if (result == nullptr) {
        result = adptr->getDefaultKif(writeAccessLevel);
    }

    return result;
}

void SamCommandProcessor::initializeDigester(const bool sessionEncryption,
                                             const bool verificationMode,
                                             const uint8_t kif,
                                             const uint8_t kvc,
                                             const std::vector<uint8_t>& digestData)
{
    mSessionEncryption = sessionEncryption;
    mVerificationMode = verificationMode;
    mKif = kif;
    mKvc = kvc;

    mLogger->debug("initialize: POREVISION = %, SAMREVISION = %, SESSIONENCRYPTION = %, " \
                   "VERIFICATIONMODE = %\n",
                   mCalypsoCard->getProductType(),
                   mSamProductType,
                   sessionEncryption,
                   verificationMode);
    mLogger->debug("initialize: VERIFICATIONMODE = %, REV32MODE = %\n",
                   verificationMode,
                   mCalypsoCard->isExtendedModeSupported());
    mLogger->debug("initialize: KIF = %, KVC %, DIGESTDATA = %\n",
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
                                               mVerificationMode,
                                               mCalypsoCard->isExtendedModeSupported(),
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
            std::make_shared<CmdSamDigestUpdate>(mSamProductType, mSessionEncryption, bytes));
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
                                                mCalypsoCard->isExtendedModeSupported() ?
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

    auto samCardRequest = std::make_shared<CardRequestAdapter>(getApduRequests(samCommands), false);

    /* Transmit CardRequest and get CardResponse */
    std::shared_ptr<CardResponseApi> samCardResponse;

    try {
        samCardResponse = mSamReader->transmitCardRequest(samCardRequest,
                                                          ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    std::vector<std::shared_ptr<ApduResponseApi>> samApduResponses =
        samCardResponse->getApduResponses();

    if (samApduResponses.size() != samCommands.size()) {
        throw DesynchronizedExchangesException("The number of commands/responses does not match: " \
                                               "cmd=" + std::to_string(samCommands.size()) + ", " +
                                               "resp="+ std::to_string(samApduResponses.size()));
    }

    /* Check all responses status */
    for (int i = 0; i < static_cast<int>(samApduResponses.size()); i++) {
        samCommands[i]->setApduResponse(samApduResponses[i]).checkStatus();
    }

    /* Get Terminal Signature from the latest response */
    auto cmdSamDigestClose = std::dynamic_pointer_cast<CmdSamDigestClose>(samCommands.back());
    cmdSamDigestClose->setApduResponse(samApduResponses[samCommands.size() - 1]);

    const std::vector<uint8_t> sessionTerminalSignature = cmdSamDigestClose->getSignature();

    mLogger->debug("SIGNATURE = %\n", ByteArrayUtil::toHex(sessionTerminalSignature));

    return sessionTerminalSignature;
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

void SamCommandProcessor::authenticateCardSignature(const std::vector<uint8_t>& cardSignatureLo)
{
    /*
     * Check the card signature part with the SAM
     * Build and send SAM Digest Authenticate command
     */
    auto cmdSamDigestAuthenticate = std::make_shared<CmdSamDigestAuthenticate>(mSamProductType,
                                                                               cardSignatureLo);

    std::vector<std::shared_ptr<ApduRequestSpi>> samApduRequests;
    samApduRequests.push_back(cmdSamDigestAuthenticate->getApduRequest());

    auto samCardRequest = std::dynamic_pointer_cast<CardRequestSpi>(
                              std::make_shared<CardRequestAdapter>(samApduRequests, false));

    std::shared_ptr<CardResponseApi> samCardResponse;
    try {
        samCardResponse = mSamReader->transmitCardRequest(samCardRequest,
                                                          ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    /* Get transaction result parsing the response */
    std::vector<std::shared_ptr<ApduResponseApi>> samApduResponses =
        samCardResponse->getApduResponses();

    if (samApduResponses.empty()) {
        throw DesynchronizedExchangesException("No response to Digest Authenticate command.");
    }

    cmdSamDigestAuthenticate->setApduResponse(samApduResponses[0]).checkStatus();
}

const std::vector<uint8_t> SamCommandProcessor::getEncryptedKey(
    const std::vector<uint8_t>& poChallenge,
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
                                                      mCalypsoCard->getCalypsoSerialNumberFull()));
        mIsDiversificationDone = true;
    }

    samCommands.push_back(std::make_shared<CmdSamGiveRandom>(mSamProductType, poChallenge));

    const int cardGenerateKeyCmdIndex = samCommands.size();

    auto cmdSamCardGenerateKey = std::make_shared<CmdSamCardGenerateKey>(mSamProductType,
                                                                         cipheringKif,
                                                                         cipheringKvc,
                                                                         sourceKif,
                                                                         sourceKvc);

    samCommands.push_back(cmdSamCardGenerateKey);

    /* Build a SAM CardRequest */
    auto samCardRequest = std::make_shared<CardRequestAdapter>(getApduRequests(samCommands), false);

    /* Execute the command */
    std::shared_ptr<CardResponseApi> samCardResponse;
    try {
        samCardResponse = mSamReader->transmitCardRequest(samCardRequest,
                                                          ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    std::shared_ptr<ApduResponseApi> cmdSamCardGenerateKeyResponse =
        samCardResponse->getApduResponses()[cardGenerateKeyCmdIndex];

    /* Check execution status */
    cmdSamCardGenerateKey->setApduResponse(cmdSamCardGenerateKeyResponse).checkStatus();

    return cmdSamCardGenerateKey->getCipheredData();
}

const std::vector<uint8_t> SamCommandProcessor::getCipheredPinData(
    const std::vector<uint8_t>& poChallenge,
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
        auto adapter = std::dynamic_pointer_cast<CardSecuritySettingAdapter>(mCardSecuritySettings);

        /* No current work key is available (outside secure session) */
        if (newPin.empty()) {
            /* PIN verification */

            if (adapter->getPinVerificationCipheringKif() == nullptr ||
                adapter->getPinVerificationCipheringKvc() == nullptr) {
                throw IllegalStateException("No KIF or KVC defined for the PIN verification " \
                                            "ciphering key");
            }

            pinCipheringKif = *adapter->getPinVerificationCipheringKif();
            pinCipheringKvc = *adapter->getPinVerificationCipheringKvc();
        } else {
            /* PIN modification */
            if (adapter->getPinModificationCipheringKif() == nullptr ||
                adapter->getPinModificationCipheringKvc() == nullptr) {
                throw IllegalStateException("No KIF or KVC defined for the PIN modification " \
                                            "ciphering key");
            }

            pinCipheringKif = *adapter->getPinModificationCipheringKif();
            pinCipheringKvc = *adapter->getPinModificationCipheringKvc();
        }
    }

    if (!mIsDiversificationDone) {
        /*
         * Build the SAM Select Diversifier command to provide the SAM with the card S/N
         * CL-SAM-CSN.1
         */
        samCommands.push_back(
            std::make_shared<CmdSamSelectDiversifier>(mSamProductType,
                                                      mCalypsoCard->getCalypsoSerialNumberFull()));
        mIsDiversificationDone = true;
    }

    if (mIsDigesterInitialized) {
        /*
         * Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list
         */
        Arrays::addAll(samCommands, getPendingSamCommands(false));
    }

    samCommands.push_back(std::make_shared<CmdSamGiveRandom>(mSamProductType, poChallenge));

    const int cardCipherPinCmdIndex = samCommands.size();

    auto cmdSamCardCipherPin = std::make_shared<CmdSamCardCipherPin>(mSamProductType,
                                                                     pinCipheringKif,
                                                                     pinCipheringKvc,
                                                                     currentPin,
                                                                     newPin);

    samCommands.push_back(cmdSamCardCipherPin);

    /* Build a SAM CardRequest */
    auto samCardRequest = std::make_shared<CardRequestAdapter>(getApduRequests(samCommands), false);

    /* Execute the command */
    std::shared_ptr<CardResponseApi> samCardResponse;
    try {
        samCardResponse = mSamReader->transmitCardRequest(samCardRequest,
                                                          ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    std::shared_ptr<ApduResponseApi> cardCipherPinResponse =
        samCardResponse->getApduResponses()[cardCipherPinCmdIndex];

    /* Check execution status */
    cmdSamCardCipherPin->setApduResponse(cardCipherPinResponse).checkStatus();

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
                                                      mCalypsoCard->getCalypsoSerialNumberFull()));
        mIsDiversificationDone = true;
    }

    if (mIsDigesterInitialized) {
        /*
         * Get the pending SAM ApduRequestAdapter and add it to the current ApduRequestAdapter list
         */
        Arrays::addAll(samCommands, getPendingSamCommands(false));
    }

    const int svPrepareOperationCmdIndex = samCommands.size();

    samCommands.push_back(cmdSamSvPrepare);

    /* Build a SAM CardRequest */
    auto samCardRequest = std::make_shared<CardRequestAdapter>(getApduRequests(samCommands), false);

    /* Execute the command */
    std::shared_ptr<CardResponseApi> samCardResponse;
    try {
        samCardResponse = mSamReader->transmitCardRequest(samCardRequest,
                                                          ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    const std::shared_ptr<ApduResponseApi> svPrepareResponse =
        samCardResponse->getApduResponses()[svPrepareOperationCmdIndex];

    /* Check execution status */
    cmdSamSvPrepare->setApduResponse(svPrepareResponse).checkStatus();

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
    /* Get the complementary data from the SAM */
    const auto cmdSamSvPrepareLoad =
        std::make_shared<CmdSamSvPrepareLoad>(mSamProductType,
                                              svGetHeader,
                                              svGetData,
                                              cmdCardSvReload->getSvReloadData());

    return getSvComplementaryData(cmdSamSvPrepareLoad);
}

const std::vector<uint8_t> SamCommandProcessor::getSvDebitComplementaryData(
    const std::shared_ptr<CmdCardSvDebit> cmdCardSvDebit,
    const std::vector<uint8_t>& svGetHeader,
    const std::vector<uint8_t>& svGetData)
{
    /* Get the complementary data from the SAM */
    const auto cmdSamSvPrepareDebit =
        std::make_shared<CmdSamSvPrepareDebit>(mSamProductType,
                                               svGetHeader,
                                               svGetData,
                                               cmdCardSvDebit->getSvDebitData());

    return getSvComplementaryData(cmdSamSvPrepareDebit);
}

const std::vector<uint8_t> SamCommandProcessor::getSvUndebitComplementaryData(
    const std::shared_ptr<CmdCardSvUndebit> cmdCardSvUndebit,
    const std::vector<uint8_t>& svGetHeader,
    const std::vector<uint8_t>& svGetData)
{
    /* Get the complementary data from the SAM */
    const auto cmdSamSvPrepareUndebit =
        std::make_shared<CmdSamSvPrepareUndebit>(mSamProductType,
                                                 svGetHeader,
                                                 svGetData,
                                                 cmdCardSvUndebit->getSvUndebitData());

    return getSvComplementaryData(cmdSamSvPrepareUndebit);
}

void SamCommandProcessor::checkSvStatus(const std::vector<uint8_t>& svOperationResponseData)
{
    std::vector<std::shared_ptr<AbstractSamCommand>> samCommands;
    const auto cmdSamSvCheck = std::make_shared<CmdSamSvCheck>(mSamProductType,
                                                               svOperationResponseData);
    samCommands.push_back(cmdSamSvCheck);

    /* Build a SAM CardRequest */
    auto samCardRequest = std::dynamic_pointer_cast<CardRequestSpi>(
                              std::make_shared<CardRequestAdapter>(getApduRequests(samCommands),
                                                                   false));

    /* Execute the command */
    std::shared_ptr<CardResponseApi> samCardResponse;
    try {
        samCardResponse = mSamReader->transmitCardRequest(samCardRequest,
                                                          ChannelControl::KEEP_OPEN);
    } catch (const UnexpectedStatusWordException& e) {
        throw IllegalStateException(UNEXPECTED_EXCEPTION,
                                    std::make_shared<UnexpectedStatusWordException>(e));
    }

    const std::shared_ptr<ApduResponseApi> svCheckResponse = samCardResponse->getApduResponses()[0];

    /* Check execution status */
    cmdSamSvCheck->setApduResponse(svCheckResponse).checkStatus();
}

}
}
}
