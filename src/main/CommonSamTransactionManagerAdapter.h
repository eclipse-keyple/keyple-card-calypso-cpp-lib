/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
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

/* Keyple Card Calypso */
#include "CommonTransactionManagerAdapter.h"
#include "SamSecuritySetting.h"
#include "SamTransactionManager.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Abstract class for all {@link SamTransactionManager} classes.
 *
 * @since 2.2.0
 */
class CommonSamTransactionManagerAdapter
: public CommonTransactionManagerAdapter<SamTransactionManager, SamSecuritySetting>,
  public SamTransactionManager {
public:
    /**
     * (package-private)<br>
     * Creates a new instance (to be used for instantiation of {@link SamTransactionManagerAdapter}
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
        const std::shared_ptr<SamSecuritySettingAdapter> securitySetting);

    /**
     * (package-private)<br>
     * Creates a new instance (to be used for instantiation of {@link
     * ControlSamTransactionManagerAdapter} only).
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
        const std::shared_ptr<CommonSecuritySettingAdapter> securitySetting,
        const std::vector<uint8_t>& defaultKeyDiversifier,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<CardReader> getSamReader() const final;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<CalypsoSam> getCalypsoSam() const final;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& prepareComputeSignature(
        const std::shared_ptr<SignatureComputationData> data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& prepareVerifySignature(
        const std::shared_ptr<SignatureVerificationData> data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SamTransactionManager& processCommands() final;

private:
    /**
     * 
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CommonSamTransactionManagerAdapter));

    /* Final fields */
    const std::shared_ptr<ProxyReaderApi> mSamReader;
    const std::shared_ptr<CalypsoSamAdapter> mSam;
    const std::shared_ptr<CommonSecuritySettingAdapter> mSecuritySetting;
    const std::vector<std::shared_ptr<AbstractSamCommand>> mSamCommands;
    const std::vector<uint8_t> mDefaultKeyDiversifier;

    /* Dynamic fields */
    std::vector<uint8_t<> mCurrentKeyDiversifier;

    /**
     * (private)<br>
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @return The card response.
     */
    virtual std::shared_ptr<CardResponseApi> transmitCardRequest(
        const std::shared_ptr<CardRequestSpi> cardRequest);

    /**
     * (package-private)<br>
     * Prepares a "SelectDiversifier" command using a specific or the default key diversifier if it is
     * not already selected.
     *
     * @param specificKeyDiversifier The specific key diversifier (optional).
     * @since 2.2.0
     */
    void prepareSelectDiversifierIfNeeded(const std::vector<uint8_t>& specificKeyDiversifier) final;

    /**
     * (package-private)<br>
     * Prepares a "SelectDiversifier" command using the default key diversifier if it is not already
     * selected.
     *
     * @since 2.2.0
     */
    void prepareSelectDiversifierIfNeeded() final;

    /**
     * (private)<br>
     * Prepares a "SelectDiversifier" command using the current key diversifier.
     *
     * @return The current instance.
     */
    virtual void prepareSelectDiversifier();
};

}
}
}
