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

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/transaction/SymmetricCryptoSecuritySetting.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerFactorySpi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::transaction::SymmetricCryptoSecuritySetting;
using keypop::calypso::crypto::symmetric::spi ::
    SymmetricCryptoCardTransactionManagerFactorySpi;

/**
 * Adapter of SymmetricCryptoSecuritySetting.
 *
 * @since 2.3.1
 */
class SymmetricCryptoSecuritySettingAdapter final
: public SymmetricCryptoSecuritySetting {
public:
    explicit SymmetricCryptoSecuritySettingAdapter(
        std::shared_ptr<SymmetricCryptoCardTransactionManagerFactorySpi>
            cryptoCardTransactionManagerFactorySpi);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& enableMultipleSession() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& enableRatificationMechanism() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& enablePinPlainTransmission() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& enableSvLoadAndDebitLog() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& authorizeSvNegativeBalance() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    SymmetricCryptoSecuritySetting& disableReadOnSessionOpening() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& assignKif(
        WriteAccessLevel writeAccessLevel,
        std::uint8_t kvc,
        std::uint8_t kif) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& assignDefaultKif(
        WriteAccessLevel writeAccessLevel, std::uint8_t kif) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting& assignDefaultKvc(
        WriteAccessLevel writeAccessLevel, std::uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting&
    addAuthorizedSessionKey(std::uint8_t kif, std::uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting&
    addAuthorizedSvKey(std::uint8_t kif, std::uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting&
    setPinVerificationCipheringKey(std::uint8_t kif, std::uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SymmetricCryptoSecuritySetting&
    setPinModificationCipheringKey(std::uint8_t kif, std::uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    void initCryptoContextForNextTransaction() override;

    /**
     * Indicates if the multiple session mode is enabled.
     *
     * @return True if the multiple session mode is enabled.
     * @since 2.0.0
     */
    bool isMultipleSessionEnabled() const;

    /**
     * Indicates if the ratification mechanism is enabled.
     *
     * @return True if the ratification mechanism is enabled.
     * @since 2.0.0
     */
    bool isRatificationMechanismEnabled() const;

    /**
     * Indicates if the transmission of the PIN in plain text is enabled.
     *
     * @return True if the transmission of the PIN in plain text is enabled.
     * @since 2.0.0
     */
    bool isPinPlainTransmissionEnabled() const;

    /**
     * Indicates if the retrieval of both load and debit log is enabled.
     *
     * @return True if the retrieval of both load and debit log is enabled.
     * @since 2.0.0
     */
    bool isSvLoadAndDebitLogEnabled() const;

    /**
     * Indicates if the SV balance is allowed to become negative.
     *
     * @return True if the retrieval of both load and debit log is enabled.
     * @since 2.0.0
     */
    bool isSvNegativeBalanceAuthorized() const;

    /**
     * @return True if the auto-read optimization feature in the "Open Secure
     * Session" command is disabled.
     * @since 2.3.2
     */
    bool isReadOnSessionOpeningDisabled() const;

    /**
     * Gets the KIF value to use for the provided write access level and KVC
     * value.
     *
     * @param writeAccessLevel The write access level.
     * @param kvc The KVC value.
     * @return Null if no KIF is available.
     * @throw IllegalArgumentException If the provided writeAccessLevel is null.
     * @since 2.0.0
     */
    std::unique_ptr<std::uint8_t>
    getKif(WriteAccessLevel writeAccessLevel, std::uint8_t kvc) const;

    /**
     * Gets the default KIF value for the provided write access level.
     *
     * @param writeAccessLevel The write access level.
     * @return Null if no KIF is available.
     * @throw IllegalArgumentException If the provided argument is null.
     * @since 2.0.0
     */
    std::shared_ptr<std::uint8_t>
    getDefaultKif(WriteAccessLevel writeAccessLevel) const;

    /**
     * Gets the default KVC value for the provided write access level.
     *
     * @param writeAccessLevel The write access level.
     * @return Null if no KVC is available.
     * @throw IllegalArgumentException If the provided argument is null.
     * @since 2.0.0
     */
    std::shared_ptr<std::uint8_t>
    getDefaultKvc(WriteAccessLevel writeAccessLevel) const;

    /**
     * Indicates if the KIF/KVC pair is authorized for a session.
     *
     * @param kif The KIF value.
     * @param kvc The KVC value.
     * @return False if KIF or KVC is null or unauthorized.
     * @since 2.0.0
     */
    bool isSessionKeyAuthorized(
        std::shared_ptr<std::uint8_t> kif,
        std::shared_ptr<std::uint8_t> kvc) const;

    /**
     * Indicates if the KIF/KVC pair is authorized for a SV operation.
     *
     * @param kif The KIF value.
     * @param kvc The KVC value.
     * @return False if KIF or KVC is null or unauthorized.
     * @since 2.0.0
     */
    bool isSvKeyAuthorized(
        std::shared_ptr<std::uint8_t> kif,
        std::shared_ptr<std::uint8_t> kvc) const;

    /**
     * Gets the KIF value of the PIN verification ciphering key.
     *
     * @return Null if no KIF is available.
     * @since 2.0.0
     */
    std::shared_ptr<std::uint8_t> getPinVerificationCipheringKif() const;

    /**
     * Gets the KVC value of the PIN verification ciphering key.
     *
     * @return Null if no KVC is available.
     * @since 2.0.0
     */
    std::shared_ptr<std::uint8_t> getPinVerificationCipheringKvc() const;

    /**
     * Gets the KIF value of the PIN modification ciphering key.
     *
     * @return Null if no KIF is available.
     * @since 2.0.0
     */
    std::shared_ptr<std::uint8_t> getPinModificationCipheringKif() const;

    /**
     * Gets the KVC value of the PIN modification ciphering key.
     *
     * @return Null if no KVC is available.
     * @since 2.0.0
     */
    std::shared_ptr<std::uint8_t> getPinModificationCipheringKvc() const;

    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactorySpi>
    getCryptoCardTransactionManagerFactorySpi() const;

    /** */
    const std::map<WriteAccessLevel, std::map<std::uint8_t, std::uint8_t>>&
    getKifMap() const;

    /** */
    const std::map<WriteAccessLevel, std::uint8_t>& getDefaultKifMap() const;

    /** */
    const std::map<WriteAccessLevel, std::uint8_t>& getDefaultKvcMap() const;

    /** */
    const std::vector<int>& getAuthorizedSessionKeys() const;

    /** */
    const std::vector<int>& getAuthorizedSvKeys() const;

private:
    /** */
    static const std::string WRITE_ACCESS_LEVEL;

    /** */
    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactorySpi>
        mCryptoCardTransactionManagerFactorySpi;

    /** */
    bool mIsMultipleSessionEnabled = false;

    /** */
    bool mIsRatificationMechanismEnabled = false;

    /** */
    bool mIsPinPlainTransmissionEnabled = false;

    /** */
    bool mIsSvLoadAndDebitLogEnabled = false;

    /** */
    bool mIsSvNegativeBalanceAuthorized = false;

    /** */
    bool mIsReadOnSessionOpeningDisabled = false;

    /** */
    std::map<WriteAccessLevel, std::map<std::uint8_t, std::uint8_t>> mKifMap;

    /** */
    std::map<WriteAccessLevel, std::uint8_t> mDefaultKifMap;

    /** */
    std::map<WriteAccessLevel, std::uint8_t> mDefaultKvcMap;

    /** */
    std::vector<int> mAuthorizedSessionKeys;

    /** */
    std::vector<int> mAuthorizedSvKeys;

    /** */
    std::shared_ptr<std::uint8_t> mPinVerificationCipheringKif;

    /** */
    std::shared_ptr<std::uint8_t> mPinVerificationCipheringKvc;

    /** */
    std::shared_ptr<std::uint8_t> mPinModificationCipheringKif;

    /** */
    std::shared_ptr<std::uint8_t> mPinModificationCipheringKvc;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
