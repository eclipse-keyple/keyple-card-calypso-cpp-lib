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

#pragma once

#include <map>
#include <memory>
#include <string>

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"
#include "CardSecuritySetting.h"
#include "WriteAccessLevel.h"

/* Calypsonet Terminal Reader */
#include "CardReader.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::sam;
using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::reader;

/**
 * (package-private)<br>
 * Implementation of CardSecuritySetting.
 *
 * @since 2.0.0
 */
class CardSecuritySettingAdapter final : public CardSecuritySetting {
public:
    /**
     * (package-private)<br>
     * Constructor.
     */
    CardSecuritySettingAdapter() ;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySetting& setSamResource(const std::shared_ptr<CardReader> samReader,
                                        const std::shared_ptr<CalypsoSam> calypsoSam) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& enableMultipleSession() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& enableRatificationMechanism() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& enablePinPlainTransmission() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& enableTransactionAudit() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& enableSvLoadAndDebitLog() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& authorizeSvNegativeBalance() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& assignKif(const WriteAccessLevel writeAccessLevel,
                                          const uint8_t kvc,
                                          const uint8_t kif) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& assignDefaultKif(const WriteAccessLevel writeAccessLevel,
                                                 const uint8_t kif) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& assignDefaultKvc(const WriteAccessLevel writeAccessLevel,
                                                 const uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& addAuthorizedSessionKey(const uint8_t kif, const uint8_t kvc);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& addAuthorizedSvKey(const uint8_t kif, const uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& setPinVerificationCipheringKey(const uint8_t kif, const uint8_t kvc)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CardSecuritySettingAdapter& setPinModificationCipheringKey(const uint8_t kif, const uint8_t kvc)
        override;

    /**
     * (package-private)<br>
     * Gets the associated SAM reader to use for secured operations.
     *
     * @return Null if no SAM reader is set.
     * @since 2.0.0
     */
    std::shared_ptr<CardReader> getSamReader() const;

    /**
     * (package-private)<br>
     * Gets the SAM used for secured operations.
     *
     * @return Null if no SAM is set or a CalypsoSam having a CalypsoSam::ProductType
     *         different from CalypsoSam::ProductType::UNKNOWN.
     * @since 2.0.0
     */
    std::shared_ptr<CalypsoSam> getCalypsoSam() const;

    /**
     * (package-private)<br>
     * Indicates if the multiple session mode is enabled.
     *
     * @return True if the multiple session mode is enabled.
     * @since 2.0.0
     */
    bool isMultipleSessionEnabled() const;

    /**
     * (package-private)<br>
     * Indicates if the ratification mechanism is enabled.
     *
     * @return True if the ratification mechanism is enabled.
     * @since 2.0.0
     */
    bool isRatificationMechanismEnabled() const;

    /**
     * (package-private)<br>
     * Indicates if the transmission of the PIN in plain text is enabled.
     *
     * @return True if the transmission of the PIN in plain text is enabled.
     * @since 2.0.0
     */
    bool isPinPlainTransmissionEnabled() const;

    /**
     * (package-private)<br>
     * Indicates if the transaction audit is enabled.
     *
     * @return True if the transaction audit is enabled.
     * @since 2.0.0
     */
    bool isTransactionAuditEnabled() const;

    /**
     * (package-private)<br>
     * Indicates if the retrieval of both load and debit log is enabled.
     *
     * @return True if the retrieval of both load and debit log is enabled.
     * @since 2.0.0
     */
    bool isSvLoadAndDebitLogEnabled() const;

    /**
     * (package-private)<br>
     * Indicates if the SV balance is allowed to become negative.
     *
     * @return True if the retrieval of both load and debit log is enabled.
     * @since 2.0.0
     */
    bool isSvNegativeBalanceAuthorized() const;

    /**
     * (package-private)<br>
     * Gets the KIF value to use for the provided write access level and KVC value.
     *
     * @param writeAccessLevel The write access level.
     * @param kvc The KVC value.
     * @return Null if no KIF is available.
     * @throws IllegalArgumentException If the provided writeAccessLevel is null.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getKif(const WriteAccessLevel writeAccessLevel,
                                          const uint8_t kvc) const;

    /**
     * (package-private)<br>
     * Gets the default KIF value for the provided write access level.
     *
     * @param writeAccessLevel The write access level.
     * @return Null if no KIF is available.
     * @throws IllegalArgumentException If the provided argument is null.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getDefaultKif(const WriteAccessLevel writeAccessLevel) const;

    /**
     * (package-private)<br>
     * Gets the default KVC value for the provided write access level.
     *
     * @param writeAccessLevel The write access level.
     * @return Null if no KVC is available.
     * @throws IllegalArgumentException If the provided argument is null.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getDefaultKvc(const WriteAccessLevel writeAccessLevel) const;

    /**
     * (package-private)<br>
     * Indicates if the KIF/KVC pair is authorized for a session.
     *
     * @param kif The KIF value.
     * @param kvc The KVC value.
     * @return False if KIF or KVC is null or unauthorized.
     * @since 2.0.0
     */
    bool isSessionKeyAuthorized(const std::shared_ptr<uint8_t> kif,
                                const std::shared_ptr<uint8_t> kvc) const;

    /**
     * (package-private)<br>
     * Indicates if the KIF/KVC pair is authorized for a SV operation.
     *
     * @param kif The KIF value.
     * @param kvc The KVC value.
     * @return False if KIF or KVC is null or unauthorized.
     * @since 2.0.0
     */
    bool isSvKeyAuthorized(const std::shared_ptr<uint8_t> kif,
                           const std::shared_ptr<uint8_t> kvc) const;

    /**
     * (package-private)<br>
     * Gets the KIF value of the PIN verification ciphering key.
     *
     * @return Null if no KIF is available.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getPinVerificationCipheringKif() const;

    /**
     * (package-private)<br>
     * Gets the KVC value of the PIN verification ciphering key.
     *
     * @return Null if no KVC is available.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getPinVerificationCipheringKvc() const;

    /**
     * (package-private)<br>
     * Gets the KIF value of the PIN modification ciphering key.
     *
     * @return Null if no KIF is available.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getPinModificationCipheringKif() const;

    /**
     * (package-private)<br>
     * Gets the KVC value of the PIN modification ciphering key.
     *
     * @return Null if no KVC is available.
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getPinModificationCipheringKvc() const;

private:
    /**
     *
     */
    static const std::string WRITE_ACCESS_LEVEL;

    /**
     *
     */
    std::shared_ptr<CardReader> mSamReader;

    /**
     *
     */
    std::shared_ptr<CalypsoSam> mCalypsoSam;

    /**
     *
     */
    bool mIsMultipleSessionEnabled;

    /**
     *
     */
    bool mIsRatificationMechanismEnabled;

    /**
     *
     */
    bool mIsPinPlainTransmissionEnabled;

    /**
     *
     */
    bool mIsTransactionAuditEnabled;

    /**
     *
     */
    bool mIsSvLoadAndDebitLogEnabled;

    /**
     *
     */
    bool mIsSvNegativeBalanceAuthorized;

    /**
     *
     */
    std::map<WriteAccessLevel, std::map<uint8_t, uint8_t>> mKifMap;

    /**
     *
     */
    std::map<WriteAccessLevel, uint8_t> mDefaultKifMap;

    /**
     *
     */
    std::map<WriteAccessLevel, uint8_t> mDefaultKvcMap;

    /**
     *
     */
    std::vector<int> mAuthorizedSessionKeys;

    /**
     *
     */
    std::vector<int> mAuthorizedSvKeys;

    /**
     *
     */
    std::shared_ptr<uint8_t> mPinVerificationCipheringKif;

    /**
     *
     */
    std::shared_ptr<uint8_t> mPinVerificationCipheringKvc;

    /**
     *
     */
    std::shared_ptr<uint8_t> mPinModificationCipheringKif;

    /**
     *
     */
    std::shared_ptr<uint8_t> mPinModificationCipheringKvc;
};

}
}
}
