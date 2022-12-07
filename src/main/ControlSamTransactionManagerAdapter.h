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
#include "CommonSamTransactionManagerAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Control SAM Transaction Manager.
 *
 * @since 2.2.0
 */
class ControlSamTransactionManagerAdapter final : public CommonSamTransactionManagerAdapter {
public:
    /**
     * (package-private)<br>
     * Creates a new instance to control a card.
     *
     * @param targetCard The target card to control provided by the selection process.
     * @param securitySetting The associated card security settings.
     * @param defaultKeyDiversifier The full serial number of the target card to be used by default
     *     when diversifying keys.
     * @param transactionAuditData The original transaction data to fill.
     * @since 2.2.0
     */
    ControlSamTransactionManagerAdapter(
        const std::shared_ptr<CalypsoCardAdapter> targetCard,
        const std::shared_ptr<CardSecuritySettingAdapter> securitySetting,
        const std::vector<uint8_t>& defaultKeyDiversifier,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * (package-private)<br>
     * Creates a new instance to control a SAM.
     *
     * @param targetSam The target SAM to control provided by the selection process.
     * @param securitySetting The associated SAM security settings.
     * @param defaultKeyDiversifier The full serial number of the target SAM to be used by default
     *     when diversifying keys.
     * @param transactionAuditData The original transaction data to fill.
     * @since 2.2.0
     */
    ControlSamTransactionManagerAdapter(
        const std::shared_ptr<CalypsoSamAdapter> targetSam,
        const std::shared_ptr<SamSecuritySettingAdapter> securitySetting,
        const std::vector<uint8_t>& defaultKeyDiversifier,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<SamSecuritySetting> getSecuritySetting() override;

private:
    /**
     * 
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(ControlSamTransactionManagerAdapter);

    /**
     * 
     */
    const std::shared_ptr<CalypsoCardAdapter> mTargetCard;
    
    /**
     * 
     */
    const std::shared_ptr<CardSecuritySettingAdapter> mCardSecuritySetting;

    /**
     * 
     */
    const std::shared_ptr<CalypsoSamAdapter> mTargetSam;

    /**
     * 
     */
    const std::shared_ptr<SamSecuritySettingAdapter> mSamSecuritySetting;
};

}
}
}
