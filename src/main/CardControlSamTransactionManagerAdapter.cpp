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

#include "CardControlSamTransactionManagerAdapter.h"

/* Keyple Card Calypso */
#include "CmdSamDigestAuthenticate.h"
#include "CmdSamDigestUpdate.h"
#include "CmdSamDigestUpdateMultiple.h"
#include "CmdSamDigestInit.h"
#include "CmdSamGiveRandom.h"
#include "CmdSamSvCheck.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "IllegalStateException.h"
#include "KeypleStd.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

/* CARD CONTROL SAM TRANSACTION MANAGER ADAPTER ------------------------------------------------- */

CardControlSamTransactionManagerAdapter::CardControlSamTransactionManagerAdapter(
  const std::shared_ptr<CalypsoCardAdapter> targetCard,
  const std::shared_ptr<CardSecuritySettingAdapter> securitySetting,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
/* CL-SAM-CSN.1 */
: CommonControlSamTransactionManagerAdapter(
      targetCard,
      std::reinterpret_pointer_cast<CommonSecuritySettingAdapter<CardSecuritySettingAdapter>>(
          securitySetting),
      targetCard->getCalypsoSerialNumberFull(),
      transactionAuditData),
  mControlSam(securitySetting ? securitySetting->getControlSam() : nullptr),
  mTargetCard(targetCard),
  mCardSecuritySetting(securitySetting) {}

std::shared_ptr<uint8_t> CardControlSamTransactionManagerAdapter::computeKvc(
    const WriteAccessLevel writeAccessLevel,
    const std::shared_ptr<uint8_t> kvc) const
{
    if (kvc != nullptr) {
        return kvc;
    }

    return mCardSecuritySetting->getDefaultKvc(writeAccessLevel);
}

std::shared_ptr<uint8_t> CardControlSamTransactionManagerAdapter::computeKif(
    const WriteAccessLevel writeAccessLevel,
    const std::shared_ptr<uint8_t> kif,
    const std::shared_ptr<uint8_t> kvc) const
{
    /* CL-KEY-KIF.1 */
    if ((kif != nullptr && *kif != 0xFF) || (kvc == nullptr)) {
        return kif;
    }

    /* CL-KEY-KIFUNK.1 */
    std::shared_ptr<uint8_t> result = mCardSecuritySetting->getKif(writeAccessLevel, *kvc);
    if (result == nullptr) {
        result = mCardSecuritySetting->getDefaultKif(writeAccessLevel);
    }

    return result;
}

SamTransactionManager& CardControlSamTransactionManagerAdapter::processCommands()
{
    /*
     * If there are pending SAM commands and the secure session is open and the "Digest Init"
     * command is not already executed, then we need to flush the session pending commands by
     * executing the pending "digest" commands "BEFORE" the other SAM commands to make sure that
     * between the session "Get Challenge" and the "Digest Init", there is no other command
     * inserted.
     */
    if (!getSamCommands().empty() &&
        mDigestManager != nullptr &&
        !mDigestManager->mIsDigestInitDone) {

        std::vector<std::shared_ptr<AbstractApduCommand>>& samCommands = getSamCommands();
        getSamCommands().clear();
        mDigestManager->prepareDigestInit();
        Arrays::addAll(getSamCommands(), samCommands);
    }

    return CommonControlSamTransactionManagerAdapter::processCommands();
}

std::shared_ptr<CmdSamGetChallenge> CardControlSamTransactionManagerAdapter::prepareGetChallenge()
{
    prepareSelectDiversifierIfNeeded();

    const auto cmd = std::make_shared<CmdSamGetChallenge>(mControlSam->getProductType(),
                                                          mTargetCard->isExtendedModeSupported() ?
                                                              8 : 4);
    getSamCommands().push_back(cmd);

    return cmd;
}

void CardControlSamTransactionManagerAdapter::prepareGiveRandom()
{
    prepareSelectDiversifierIfNeeded();

    getSamCommands().push_back(std::make_shared<CmdSamGiveRandom>(mControlSam->getProductType(),
                                                                  mTargetCard->getCardChallenge()));
}

const std::shared_ptr<CmdSamCardGenerateKey>
    CardControlSamTransactionManagerAdapter::prepareCardGenerateKey(const uint8_t cipheringKif,
                                                                    const uint8_t cipheringKvc,
                                                                    const uint8_t sourceKif,
                                                                    const uint8_t sourceKvc)
{
    const auto cmd = std::make_shared<CmdSamCardGenerateKey>(mControlSam->getProductType(),
                                                             cipheringKif,
                                                             cipheringKvc,
                                                             sourceKif,
                                                             sourceKvc);
    getSamCommands().push_back(cmd);

    return cmd;
}

const std::shared_ptr<CmdSamCardCipherPin>
    CardControlSamTransactionManagerAdapter::prepareCardCipherPin(
        const std::vector<uint8_t>& currentPin,
        const std::vector<uint8_t>& newPin)
{
    uint8_t pinCipheringKif;
    uint8_t pinCipheringKvc;

    if (mDigestManager != nullptr && mDigestManager->mSessionKif != 0) {
        /* The current work key has been set (a secure session is open) */
        pinCipheringKif = mDigestManager->mSessionKif;
        pinCipheringKvc = mDigestManager->mSessionKvc;

    } else {
        /* No current work key is available (outside secure session) */
        if (newPin.empty()) {
            /* PIN verification */
            if (mCardSecuritySetting->getPinVerificationCipheringKif() == nullptr ||
                mCardSecuritySetting->getPinVerificationCipheringKvc() == nullptr) {
                throw IllegalStateException("No KIF or KVC defined for the PIN verification " \
                                            "ciphering key");
            }

            pinCipheringKif = *mCardSecuritySetting->getPinVerificationCipheringKif();
            pinCipheringKvc = *mCardSecuritySetting->getPinVerificationCipheringKvc();
        } else {
            /* PIN modification */
            if (mCardSecuritySetting->getPinModificationCipheringKif() == nullptr ||
                mCardSecuritySetting->getPinModificationCipheringKvc() == nullptr) {
                throw IllegalStateException("No KIF or KVC defined for the PIN modification " \
                                            "ciphering key");
            }

            pinCipheringKif = *mCardSecuritySetting->getPinModificationCipheringKif();
            pinCipheringKvc = *mCardSecuritySetting->getPinModificationCipheringKvc();
        }
    }

    const auto cmd = std::make_shared<CmdSamCardCipherPin>(mControlSam->getProductType(),
                                                           pinCipheringKif,
                                                           pinCipheringKvc,
                                                           currentPin,
                                                           newPin);
    getSamCommands().push_back(cmd);

    return cmd;
}

const std::shared_ptr<CmdSamSvPrepareLoad>
    CardControlSamTransactionManagerAdapter::prepareSvPrepareLoad(
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData,
        const std::shared_ptr<CmdCardSvReload> cmdCardSvReload)
{
    prepareSelectDiversifierIfNeeded();
    const auto cmd = std::make_shared<CmdSamSvPrepareLoad>(mControlSam->getProductType(),
                                                           svGetHeader,
                                                           svGetData,
                                                           cmdCardSvReload->getSvReloadData());
    getSamCommands().push_back(cmd);

    return cmd;
}

const std::shared_ptr<CmdSamSvPrepareDebitOrUndebit>
    CardControlSamTransactionManagerAdapter::prepareSvPrepareDebitOrUndebit(
        const bool isDebitCommand,
        const std::vector<uint8_t>& svGetHeader,
        const std::vector<uint8_t>& svGetData,
        const std::shared_ptr<CmdCardSvDebitOrUndebit> cmdCardSvDebitOrUndebit)
{
    prepareSelectDiversifierIfNeeded();
    const auto cmd = std::make_shared<CmdSamSvPrepareDebitOrUndebit>(
                         isDebitCommand,
                         mControlSam->getProductType(),
                         svGetHeader,
                         svGetData,
                         cmdCardSvDebitOrUndebit->getSvDebitOrUndebitData());
    getSamCommands().push_back(cmd);

    return cmd;
}

void CardControlSamTransactionManagerAdapter::prepareSvCheck(
    const std::vector<uint8_t>& svOperationData)
{
    getSamCommands().push_back(std::make_shared<CmdSamSvCheck>(mControlSam->getProductType(),
                                                               svOperationData));
}

void CardControlSamTransactionManagerAdapter::initializeSession(
    const std::vector<uint8_t>& openSecureSessionDataOut,
    const uint8_t kif,
    const uint8_t kvc,
    const bool isSessionEncrypted,
    const bool isVerificationMode)
{
    mDigestManager = std::make_shared<DigestManager>(this,
                                                     openSecureSessionDataOut,
                                                     kif,
                                                     kvc,
                                                     isSessionEncrypted,
                                                     isVerificationMode);
}

void CardControlSamTransactionManagerAdapter::updateSession(
    const std::vector<std::shared_ptr<ApduRequestSpi>>& requests,
    const std::vector<std::shared_ptr<ApduResponseApi>>& responses,
    const int startIndex)
{
    mDigestManager->updateSession(requests, responses, startIndex);
}

const std::shared_ptr<CmdSamDigestClose>
    CardControlSamTransactionManagerAdapter::prepareSessionClosing()
{
    mDigestManager->prepareCommands();
    mDigestManager = nullptr;

    return std::dynamic_pointer_cast<CmdSamDigestClose>(
               getSamCommands()[getSamCommands().size() - 1]);
}

void CardControlSamTransactionManagerAdapter::prepareDigestAuthenticate(
    const std::vector<uint8_t>& cardSignatureLo)
{
    getSamCommands().push_back(std::make_shared<CmdSamDigestAuthenticate>(
                                   mControlSam->getProductType(),
                                   cardSignatureLo));
}

/* DIGEST MANAGER ------------------------------------------------------------------------------- */

CardControlSamTransactionManagerAdapter::DigestManager::DigestManager(
  CardControlSamTransactionManagerAdapter* parent,
  const std::vector<uint8_t>& openSecureSessionDataOut,
  const uint8_t kif,
  const uint8_t kvc,
  const bool isSessionEncrypted,
  const bool isVerificationMode)
: mSessionKif(kif),
  mSessionKvc(kvc),
  mOpenSecureSessionDataOut(openSecureSessionDataOut),
  mIsSessionEncrypted(isSessionEncrypted),
  mIsVerificationMode(isVerificationMode),
  mParent(parent) {}

void CardControlSamTransactionManagerAdapter::DigestManager::updateSession(
    const std::vector<std::shared_ptr<ApduRequestSpi>>& requests,
    const std::vector<std::shared_ptr<ApduResponseApi>>& responses,
    const int startIndex)
{
    for (int i = startIndex; i < static_cast<int>(requests.size()); i++) {
        /*
         * If the request is of case4 type, LE must be excluded from the digest computation. In this
         * case, we remove here the last byte of the command buffer.
         * CL-C4-MAC.1
         */
        const std::shared_ptr<ApduRequestSpi> request = requests[i];
        mCardApdus.push_back(ApduUtil::isCase4(request->getApdu()) ?
                                 Arrays::copyOfRange(request->getApdu(),
                                                     0,
                                                     request->getApdu().size() - 1) :
                                 request->getApdu());

        const std::shared_ptr<ApduResponseApi> response = responses[i];
        mCardApdus.push_back(response->getApdu());
    }
}

void CardControlSamTransactionManagerAdapter::DigestManager::prepareCommands()
{
    /* Prepare the "Digest Init" command if not already done */
    if (!mIsDigestInitDone) {
        prepareDigestInit();
    }

    /* Prepare the "Digest Update" commands and flush the buffer */
    prepareDigestUpdate();
    mCardApdus.clear();

    /* Prepare the "Digest Close" command */
    prepareDigestClose();
}

void CardControlSamTransactionManagerAdapter::DigestManager::prepareDigestInit()
{
    /* CL-SAM-DINIT.1 */
    mParent->getSamCommands().push_back(std::make_shared<CmdSamDigestInit>(
                                            mParent->mControlSam->getProductType(),
                                            mIsVerificationMode,
                                            mParent->mTargetCard->isExtendedModeSupported(),
                                            mSessionKif,
                                            mSessionKvc,
                                            mOpenSecureSessionDataOut));

    mIsDigestInitDone = true;
}

void CardControlSamTransactionManagerAdapter::DigestManager::prepareDigestUpdate()
{
    if (mCardApdus.empty()) {
        return;
    }

    /* CL-SAM-DUPDATE.1 */
    if (mParent->mControlSam->getProductType() == CalypsoSam::ProductType::SAM_C1) {

        /*
         * Digest Update Multiple
         * Construct list of DataIn
         */
        std::vector<std::vector<uint8_t>> digestDataList;
        std::vector<uint8_t> buffer(255);
        int i = 0;

        for (const auto& cardApdu : mCardApdus) {
            if (static_cast<int>(i + cardApdu.size()) > 254) {
                /* Copy buffer to digestDataList and reset buffer */
                digestDataList.push_back(Arrays::copyOf(buffer, i));
                i = 0;
            }

            /* Add [length][apdu] to current buffer */
            buffer[i++] = static_cast<uint8_t>(cardApdu.size());
            System::arraycopy(cardApdu, 0, buffer, i, cardApdu.size());
            i += cardApdu.size();
        }

        /* Copy buffer to digestDataList */
        digestDataList.push_back(Arrays::copyOf(buffer, i));

        /* Add commands */
        for (const auto& dataIn : digestDataList) {
            mParent->getSamCommands().push_back(
                std::make_shared<CmdSamDigestUpdateMultiple>(mParent->mControlSam->getProductType(),
                                                             dataIn));
        }

    } else {
        /* Digest Update (simple) */
        for (const auto& cardApdu : mCardApdus) {
            mParent->getSamCommands().push_back(
                std::make_shared<CmdSamDigestUpdate>(mParent->mControlSam->getProductType(),
                                                     mIsSessionEncrypted,
                                                     cardApdu));
        }
    }
}

void CardControlSamTransactionManagerAdapter::DigestManager::prepareDigestClose()
{
    /* CL-SAM-DCLOSE.1 */
    mParent->getSamCommands().push_back(std::make_shared<CmdSamDigestClose>(
                                            mParent->mControlSam->getProductType(),
                                            mParent->mTargetCard->isExtendedModeSupported() ?
                                                8 : 4));
}

}
}
}
